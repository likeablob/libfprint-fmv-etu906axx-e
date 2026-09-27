/*
 * Driver for Egis Technology (LighTuning) Match-On-Chip sensors
 * Copyright (C) 2023-2025 Joshua Grisham <josh@joshuagrisham.com>
 *
 * Portions of code and logic inspired from the elanmoc libfprint driver
 * which is copyright (C) 2021 Elan Microelectronics Inc (see elanmoc.c)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define FP_COMPONENT "egismoc"
#include "fpi-log.h"

#include <stdio.h>
#include <glib.h>
#include <sys/param.h>

#include "drivers_api.h"
#include "fpi-byte-writer.h"

#include "egismoc.h"

struct _FpiDeviceEgisMoc
{
  FpDevice        parent;
  FpiSsm         *task_ssm;
  FpiSsm         *cmd_ssm;
  FpiUsbTransfer *cmd_transfer;
  GPtrArray      *enrolled_ids;
  GBytes         *enrollment_nonce;
  gint            max_enroll_stages;
  FpiSsm         *wait_finger_ssm;
  gint64          wait_finger_start;
  GCancellable   *interrupt_cancellable;
  gboolean        dev_init_done;
};

G_DEFINE_TYPE (FpiDeviceEgisMoc, fpi_device_egismoc, FP_TYPE_SDCP_DEVICE);

static const FpIdEntry egismoc_id_table[] = {
  { .vid = 0x1c7a, .pid = 0x0582, .driver_data = EGISMOC_DRIVER_CHECK_PREFIX_TYPE1 },
  { .vid = 0x1c7a, .pid = 0x0583, .driver_data = EGISMOC_DRIVER_CHECK_PREFIX_TYPE1 | EGISMOC_DRIVER_MAX_ENROLL_STAGES_15 },
  { .vid = 0x1c7a, .pid = 0x0584, .driver_data = EGISMOC_DRIVER_CHECK_PREFIX_TYPE1 | EGISMOC_DRIVER_MAX_ENROLL_STAGES_20 },
  { .vid = 0x1c7a, .pid = 0x0586, .driver_data = EGISMOC_DRIVER_CHECK_PREFIX_TYPE1 | EGISMOC_DRIVER_MAX_ENROLL_STAGES_20 },
  { .vid = 0x1c7a, .pid = 0x0587, .driver_data = EGISMOC_DRIVER_CHECK_PREFIX_TYPE1 | EGISMOC_DRIVER_MAX_ENROLL_STAGES_20 },
  { .vid = 0x1c7a, .pid = 0x05a1, .driver_data = EGISMOC_DRIVER_CHECK_PREFIX_TYPE2 },
  { .vid = 0x1c7a, .pid = 0x05a5, .driver_data = EGISMOC_DRIVER_CHECK_PREFIX_TYPE2 | EGISMOC_DRIVER_MAX_ENROLL_STAGES_15 },
  { .vid = 0x1c7a, .pid = 0x05b1, .driver_data = EGISMOC_DRIVER_CHECK_PREFIX_TYPE2 | EGISMOC_DRIVER_MAX_ENROLL_STAGES_20 },
  { .vid = 0,      .pid = 0,      .driver_data = 0 }
};

typedef void (*SynCmdMsgCallback) (FpDevice *device,
                                   guchar   *buffer_in,
                                   gsize     length_in,
                                   GError   *error);

typedef struct egismoc_command_data
{
  SynCmdMsgCallback callback;
} CommandData;

typedef struct egismoc_enroll_print
{
  FpPrint *print;
  int      stage;
} EnrollPrint;

typedef struct egismoc_identify_print
{
  GBytes *id;
  GBytes *mac;
  GError *error;
} IdentifyPrint;

static gboolean
egismoc_validate_response_prefix (const guchar *buffer_in,
                                  const gsize   buffer_in_len,
                                  const guchar *valid_prefix,
                                  const gsize   valid_prefix_len)
{
  const gboolean result = memcmp (buffer_in +
                                  (egismoc_read_prefix_len +
                                   EGISMOC_CHECK_BYTES_LENGTH),
                                  valid_prefix,
                                  valid_prefix_len) == 0;

  fp_dbg ("Response prefix valid: %s", result ? "yes" : "NO");
  return result;
}

static gboolean
egismoc_validate_response_suffix (const guchar *buffer_in,
                                  const gsize   buffer_in_len,
                                  const guchar *valid_suffix,
                                  const gsize   valid_suffix_len)
{
  const gboolean result = memcmp (buffer_in + (buffer_in_len - valid_suffix_len),
                                  valid_suffix,
                                  valid_suffix_len) == 0;

  fp_dbg ("Response suffix valid: %s", result ? "yes" : "NO");
  return result;
}

static void
egismoc_task_ssm_done (FpiSsm   *ssm,
                       FpDevice *device,
                       GError   *error)
{
  fp_dbg ("Task SSM done");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  /* task_ssm is going to be freed by completion of SSM */
  g_assert (!self->task_ssm || self->task_ssm == ssm);
  self->task_ssm = NULL;

  g_clear_pointer (&self->enrolled_ids, g_ptr_array_unref);

  if (error)
    fpi_device_action_error (device, error);
}

static void
egismoc_task_ssm_next_state_cb (FpDevice *device,
                                guchar   *buffer_in,
                                gsize     length_in,
                                GError   *error)
{
  fp_dbg ("Task SSM next state callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  if (error)
    fpi_ssm_mark_failed (self->task_ssm, error);
  else
    fpi_ssm_next_state (self->task_ssm);
}

static void
egismoc_cmd_receive_cb (FpiUsbTransfer *transfer,
                        FpDevice       *device,
                        gpointer        userdata,
                        GError         *error)
{
  g_autofree guchar *buffer = NULL;
  CommandData *data = userdata;
  SynCmdMsgCallback callback;
  gssize actual_length;

  fp_dbg ("Command receive callback");

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  if (data == NULL || transfer->actual_length < egismoc_read_prefix_len)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }

  /* Let's complete the previous ssm and then handle the callback, so that
   * we are sure that we won't start a transfer or a new command while there is
   * another one still ongoing
   */
  callback = data->callback;
  buffer = g_steal_pointer (&transfer->buffer);
  actual_length = transfer->actual_length;

  fpi_ssm_mark_completed (transfer->ssm);

  if (callback)
    callback (device, buffer, actual_length, NULL);
}

static void
egismoc_cmd_run_state (FpiSsm   *ssm,
                       FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  g_autoptr(FpiUsbTransfer) transfer = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CMD_SEND:
      if (self->cmd_transfer)
        {
          self->cmd_transfer->ssm = ssm;
          fpi_usb_transfer_submit (g_steal_pointer (&self->cmd_transfer),
                                   EGISMOC_USB_SEND_TIMEOUT,
                                   fpi_device_get_cancellable (device),
                                   fpi_ssm_usb_transfer_cb,
                                   NULL);
          break;
        }

      fpi_ssm_next_state (ssm);
      break;

    case CMD_GET:
      transfer = fpi_usb_transfer_new (device);
      transfer->ssm = ssm;
      fpi_usb_transfer_fill_bulk (transfer, EGISMOC_EP_CMD_IN,
                                  EGISMOC_USB_IN_RECV_LENGTH);
      fpi_usb_transfer_submit (g_steal_pointer (&transfer),
                               EGISMOC_USB_RECV_TIMEOUT,
                               fpi_device_get_cancellable (device),
                               egismoc_cmd_receive_cb,
                               fpi_ssm_get_data (ssm));
      break;
    }
}

static void
egismoc_cmd_ssm_done (FpiSsm   *ssm,
                      FpDevice *device,
                      GError   *error)
{
  g_autoptr(GError) local_error = error;
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  CommandData *data = fpi_ssm_get_data (ssm);

  g_assert (self->cmd_ssm == ssm);
  g_assert (!self->cmd_transfer || self->cmd_transfer->ssm == ssm);

  self->cmd_ssm = NULL;
  self->cmd_transfer = NULL;

  if (error && data && data->callback)
    data->callback (device, NULL, 0, g_steal_pointer (&local_error));
}

/*
 * Derive the 2 "check bytes" for write payloads
 * 32-bit big-endian sum of all 16-bit words (including check bytes) MOD 0xFFFF
 * should be 0, otherwise the device will reject the payload
 */
static guint16
egismoc_get_check_bytes (FpiByteReader *reader)
{
  fp_dbg ("Get check bytes");
  size_t sum_values = 0;
  guint16 val;

  fpi_byte_reader_set_pos (reader, 0);

  while (fpi_byte_reader_get_uint16_be (reader, &val))
    sum_values += val;

  return G_MAXUINT16 - (sum_values % G_MAXUINT16);
}

static void
egismoc_exec_cmd (FpDevice         *device,
                  guchar           *cmd,
                  const gsize       cmd_length,
                  GDestroyNotify    cmd_destroy,
                  SynCmdMsgCallback callback)
{
  g_auto(FpiByteWriter) writer = {0};
  g_autoptr(FpiUsbTransfer) transfer = NULL;
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  g_autofree CommandData *data = NULL;
  gsize buffer_out_length = 0;
  gboolean written = TRUE;
  guint16 check_value;

  fp_dbg ("Execute command and get response");

  /*
   * buffer_out should be a fully composed command (with prefix, check bytes, etc)
   * which looks like this:
   *   E G I S 00 00 00 01 {cb1} {cb2} {payload}
   * where cb1 and cb2 are some check bytes generated by the
   * egismoc_get_check_bytes() method and payload is what is passed via the cmd
   * parameter
   */
  buffer_out_length = egismoc_write_prefix_len
                      + EGISMOC_CHECK_BYTES_LENGTH
                      + cmd_length;

  fpi_byte_writer_init_with_size (&writer, buffer_out_length +
                                  (buffer_out_length % 2 ? 1 : 0), TRUE);

  /* Prefix */
  written &= fpi_byte_writer_put_data (&writer, egismoc_write_prefix,
                                       egismoc_write_prefix_len);

  /* Check Bytes - leave them as 00 for now then later generate and copy over
   * the real ones */
  written &= fpi_byte_writer_change_pos (&writer, EGISMOC_CHECK_BYTES_LENGTH);

  /* Command Payload */
  written &= fpi_byte_writer_put_data (&writer, cmd, cmd_length);

  /* Now fetch and set the "real" check bytes based on the currently
   * assembled payload */
  check_value = egismoc_get_check_bytes (FPI_BYTE_READER (&writer));
  fpi_byte_writer_set_pos (&writer, egismoc_write_prefix_len);
  written &= fpi_byte_writer_put_uint16_be (&writer, check_value);

  /* destroy cmd if requested */
  if (cmd_destroy)
    g_clear_pointer (&cmd, cmd_destroy);

  g_assert (self->cmd_ssm == NULL);
  self->cmd_ssm = fpi_ssm_new (device,
                               egismoc_cmd_run_state,
                               CMD_STATES);

  data = g_new0 (CommandData, 1);
  data->callback = callback;
  fpi_ssm_set_data (self->cmd_ssm, g_steal_pointer (&data), g_free);

  if (!written)
    {
      fpi_ssm_start (self->cmd_ssm, egismoc_cmd_ssm_done);
      fpi_ssm_mark_failed (self->cmd_ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  transfer = fpi_usb_transfer_new (device);
  transfer->short_is_error = TRUE;
  transfer->ssm = self->cmd_ssm;

  fpi_usb_transfer_fill_bulk_full (transfer,
                                   EGISMOC_EP_CMD_OUT,
                                   fpi_byte_writer_reset_and_get_data (&writer),
                                   buffer_out_length,
                                   g_free);

  g_assert (self->cmd_transfer == NULL);
  self->cmd_transfer = g_steal_pointer (&transfer);
  fpi_ssm_start (self->cmd_ssm, egismoc_cmd_ssm_done);
}

static void
egismoc_wait_finger_ssm_done (FpiSsm   *ssm,
                              FpDevice *device,
                              GError   *error)
{
  fp_dbg ("Wait for finger SSM done");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  /* wait_finger_ssm is going to be freed by completion of SSM */
  g_assert (!self->wait_finger_ssm || self->wait_finger_ssm == ssm);

  self->wait_finger_ssm = NULL;
  self->wait_finger_start = 0;

  if (error && g_strcmp0 (error->message, "Operation was cancelled") != 0)
    fpi_device_action_error (device, error);
}

static void
egismoc_finger_on_sensor_cb (FpiUsbTransfer *transfer,
                             FpDevice       *device,
                             gpointer        userdata,
                             GError         *error)
{
  fp_dbg ("Finger on sensor callback");

  g_return_if_fail (transfer->ssm);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  /* finger is "present" when buffer begins with "SIGE" and ends in valid suffix */
  if (memcmp (transfer->buffer, egismoc_read_prefix, 4) == 0 &&
      egismoc_validate_response_suffix (transfer->buffer,
                                        transfer->actual_length,
                                        rsp_sensor_has_finger_suffix,
                                        rsp_sensor_has_finger_suffix_len))
    {
      fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);
      fpi_ssm_next_state (transfer->ssm);
    }
  else
    {
      fpi_ssm_jump_to_state (transfer->ssm, WAIT_FINGER_NOT_ON_SENSOR);
    }
}

static void
egismoc_wait_finger_run_state (FpiSsm   *ssm,
                               FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  g_autoptr(FpiUsbTransfer) transfer = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case WAIT_FINGER_NOT_ON_SENSOR:
      if (self->wait_finger_start + EGISMOC_FINGER_ON_SENSOR_TIMEOUT_USEC > g_get_monotonic_time ())
        {
          transfer = fpi_usb_transfer_new (device);
          fpi_usb_transfer_fill_interrupt (transfer, EGISMOC_EP_CMD_INTERRUPT_IN,
                                           EGISMOC_USB_INTERRUPT_IN_RECV_LENGTH);

          transfer->ssm = ssm;
          /* Interrupt on this device always returns 1 byte short; this is expected */
          transfer->short_is_error = FALSE;

          fpi_usb_transfer_submit (g_steal_pointer (&transfer),
                                   EGISMOC_USB_INTERRUPT_TIMEOUT,
                                   self->interrupt_cancellable,
                                   egismoc_finger_on_sensor_cb,
                                   NULL);
        }
      else
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                              "Timed out trying to detect "
                                                              "finger on sensor"));
        }
      break;

    case WAIT_FINGER_ON_SENSOR:
      fpi_ssm_mark_completed (ssm);
      fpi_ssm_next_state (self->task_ssm);
      break;
    }
}

static void
egismoc_wait_finger_on_sensor (FpDevice *device)
{
  fp_dbg ("Wait for finger on sensor");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  self->wait_finger_start = g_get_monotonic_time ();

  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NEEDED);

  g_assert (self->wait_finger_ssm == NULL);
  self->wait_finger_ssm = fpi_ssm_new (device, egismoc_wait_finger_run_state, WAIT_FINGER_STATES);
  fpi_ssm_start (self->wait_finger_ssm, egismoc_wait_finger_ssm_done);
}

static void
egismoc_list_fill_enrolled_ids_cb (FpDevice *device,
                                   guchar   *buffer_in,
                                   gsize     length_in,
                                   GError   *error)
{
  fp_dbg ("List callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  const guint8 *data;
  guchar *enrollment_id = NULL;
  FpiByteReader reader;
  gboolean read = TRUE;

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  g_clear_pointer (&self->enrolled_ids, g_ptr_array_unref);
  self->enrolled_ids = g_ptr_array_new_with_free_func (g_free);

  fpi_byte_reader_init (&reader, buffer_in, length_in);

  read &= fpi_byte_reader_set_pos (&reader, EGISMOC_LIST_RESPONSE_PREFIX_SIZE);

  /*
   * Each enrollment_id will be returned in this response as a 32 byte array
   * The other stuff in the payload is 16 bytes long, so if there is at least 1
   * print then the length should be at least 16+32=48 bytes long
   */
  while (read)
    {
      read &= fpi_byte_reader_get_data (&reader, SDCP_ENROLLMENT_ID_SIZE, &data);
      if (!read)
        break;

      enrollment_id = g_malloc0 (SDCP_ENROLLMENT_ID_SIZE);
      memcpy (enrollment_id, data, SDCP_ENROLLMENT_ID_SIZE);

      fp_dbg ("Device ID %0d:", self->enrolled_ids->len + 1);
      fp_dbg_hex_dump_bytes (enrollment_id, SDCP_ENROLLMENT_ID_SIZE);

      g_ptr_array_add (self->enrolled_ids, g_steal_pointer (&enrollment_id));
      g_free (enrollment_id);
    }

  fp_info ("Number of currently enrolled fingerprints on the device is %d",
           self->enrolled_ids->len);

  if (self->task_ssm)
    fpi_ssm_next_state (self->task_ssm);
}

static void
egismoc_list_run_state (FpiSsm   *ssm,
                        FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  FpSdcpDevice *sdcp_device = FP_SDCP_DEVICE (device);

  g_autoptr(GPtrArray) ids = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case LIST_GET_ENROLLED_IDS:
      egismoc_exec_cmd (device, cmd_list, cmd_list_len, NULL,
                        egismoc_list_fill_enrolled_ids_cb);
      break;

    case LIST_RETURN_ENROLLED_PRINTS:
      ids = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
      for (gint i = 0; i < self->enrolled_ids->len; i++)
        {
          GBytes *id = g_bytes_new (g_ptr_array_index (self->enrolled_ids, i),
                                    SDCP_ENROLLMENT_ID_SIZE);
          g_ptr_array_add (ids, g_steal_pointer (&id));
        }
      fpi_sdcp_device_list_complete (sdcp_device, g_steal_pointer (&ids), NULL);
      fpi_ssm_next_state (ssm);
      break;
    }
}

static void
egismoc_list (FpSdcpDevice *sdcp_device)
{
  fp_dbg ("List");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (sdcp_device);

  g_assert (self->task_ssm == NULL);
  self->task_ssm = fpi_ssm_new (FP_DEVICE (sdcp_device),
                                egismoc_list_run_state,
                                LIST_STATES);
  fpi_ssm_start (self->task_ssm, egismoc_task_ssm_done);
}

static guchar *
egismoc_get_delete_cmd (FpDevice *device,
                        FpPrint  *delete_print,
                        gsize    *length_out)
{
  fp_dbg ("Get delete command");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  g_auto(FpiByteWriter) writer = {0};
  g_autoptr(GBytes) enrollment_id = NULL;
  g_autofree guchar *result = NULL;
  gboolean written = TRUE;

  /*
   * The final command body should contain:
   * 1) hard-coded 00 00
   * 2) 2-byte size indiciator, 20*Number deleted identifiers plus 7 in form of:
   *    num_to_delete * 0x20 + 0x07
   *    Since max prints can be higher than 7 then this goes up to 2 bytes
   *    (e9 + 9 = 109)
   * 3) Hard-coded prefix (cmd_delete_prefix)
   * 4) 2-byte size indiciator, 20*Number of enrolled identifiers without plus 7
   *    (num_to_delete * 0x20)
   * 5) All of the currently registered prints to delete in their 32-byte device
   *    identifiers (enrolled_list)
   */

  int num_to_delete = 0;
  if (delete_print)
    num_to_delete = 1;
  else if (self->enrolled_ids)
    num_to_delete = self->enrolled_ids->len;

  const gsize body_length = sizeof (guchar) * SDCP_ENROLLMENT_ID_SIZE * num_to_delete;
  /* total_length is the 6 various bytes plus prefix and body payload */
  const gsize total_length = (sizeof (guchar) * 6) + cmd_delete_prefix_len + body_length;

  /* pre-fill entire payload with 00s */
  fpi_byte_writer_init_with_size (&writer, total_length, TRUE);

  /* start with 00 00 (just move starting offset up by 2) */
  written &= fpi_byte_writer_set_pos (&writer, 2);

  /* Size Counter bytes */
  /* "easiest" way to handle 2-bytes size for counter is to hard-code logic for
   * when we go to the 2nd byte
   * note this will not work in case any model ever supports more than 14 prints
   * (assumed max is 10) */
  if (num_to_delete > 7)
    {
      written &= fpi_byte_writer_put_uint8 (&writer, 0x01);
      written &= fpi_byte_writer_put_uint8 (&writer, ((num_to_delete - 8) * 0x20) + 0x07);
    }
  else
    {
      /* first byte is 0x00, just skip it */
      written &= fpi_byte_writer_change_pos (&writer, 1);
      written &= fpi_byte_writer_put_uint8 (&writer, (num_to_delete * 0x20) + 0x07);
    }

  /* command prefix */
  written &= fpi_byte_writer_put_data (&writer, cmd_delete_prefix,
                                       cmd_delete_prefix_len);

  /* 2-bytes size logic for counter again */
  if (num_to_delete > 7)
    {
      written &= fpi_byte_writer_put_uint8 (&writer, 0x01);
      written &= fpi_byte_writer_put_uint8 (&writer, (num_to_delete - 8) * 0x20);
    }
  else
    {
      /* first byte is 0x00, just skip it */
      written &= fpi_byte_writer_change_pos (&writer, 1);
      written &= fpi_byte_writer_put_uint8 (&writer, num_to_delete * 0x20);
    }

  /* append desired enrollment_id(s) */

  /* if passed a delete_print then fetch its ID from the FpPrint */
  if (delete_print)
    {
      fpi_sdcp_device_get_print_id (delete_print, &enrollment_id);
      if (!enrollment_id)
        {
          fpi_ssm_mark_failed (self->task_ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                         "Print data missing ID"));
          return NULL;
        }

      fp_dbg ("Delete enrollment ID:");
      fp_dbg_hex_dump_gbytes (enrollment_id);

      written &= fpi_byte_writer_put_data (&writer,
                                           g_bytes_get_data (enrollment_id, NULL),
                                           g_bytes_get_size (enrollment_id));
    }
  /* Otherwise assume this is a "clear" - just loop through and append all enrolled IDs */
  else if (self->enrolled_ids)
    {
      for (guint i = 0; i < self->enrolled_ids->len && written; i++)
        {
          written &= fpi_byte_writer_put_data (&writer,
                                               g_ptr_array_index (self->enrolled_ids, i),
                                               SDCP_ENROLLMENT_ID_SIZE);
        }
    }

  g_assert (written);

  if (length_out)
    *length_out = total_length;

  return fpi_byte_writer_reset_and_get_data (&writer);
}

static void
egismoc_delete_cb (FpDevice *device,
                   guchar   *buffer_in,
                   gsize     length_in,
                   GError   *error)
{
  fp_dbg ("Delete callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  /* Check that the read payload indicates "success" with the delete */
  if (egismoc_validate_response_prefix (buffer_in,
                                        length_in,
                                        rsp_delete_success_prefix,
                                        rsp_delete_success_prefix_len))
    {
      if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_CLEAR_STORAGE)
        {
          fpi_device_clear_storage_complete (device, NULL);
          fpi_ssm_next_state (self->task_ssm);
        }
      else if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_DELETE)
        {
          fpi_device_delete_complete (device, NULL);
          fpi_ssm_next_state (self->task_ssm);
        }
      else
        {
          fpi_ssm_mark_failed (self->task_ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "Unsupported delete action"));
        }
    }
  else
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "Delete print was not successful"));
    }
}

static void
egismoc_delete_run_state (FpiSsm   *ssm,
                          FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  g_autofree guchar *payload = NULL;
  gsize payload_length = 0;
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case DELETE_GET_ENROLLED_IDS:
      /* get enrolled_ids from device for use building delete payload below */
      egismoc_exec_cmd (device, cmd_list, cmd_list_len, NULL,
                        egismoc_list_fill_enrolled_ids_cb);
      break;

    case DELETE_DELETE:
      if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_DELETE)
        {
          payload = egismoc_get_delete_cmd (device, fpi_ssm_get_data (ssm),
                                            &payload_length);
        }
      else
        {
          if (self->enrolled_ids->len == 0)
            {
              error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_NOT_FOUND,
                                                "Clear attempted when there are no prints "
                                                "currently stored on the device");
              fpi_device_delete_complete (device, error);
              fpi_ssm_mark_failed (self->task_ssm, error);
              return;
            }

          payload = egismoc_get_delete_cmd (device, NULL, &payload_length);
        }

      egismoc_exec_cmd (device, g_steal_pointer (&payload), payload_length,
                        g_free, egismoc_delete_cb);
      break;
    }
}

static void
egismoc_clear_storage (FpDevice *device)
{
  fp_dbg ("Clear storage");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  g_assert (self->task_ssm == NULL);
  self->task_ssm = fpi_ssm_new (device,
                                egismoc_delete_run_state,
                                DELETE_STATES);
  fpi_ssm_start (self->task_ssm, egismoc_task_ssm_done);
}

static void
egismoc_delete (FpDevice *device)
{
  fp_dbg ("Delete");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  FpPrint *delete_print = NULL;

  fpi_device_get_delete_data (device, &delete_print);

  g_assert (self->task_ssm == NULL);
  self->task_ssm = fpi_ssm_new (device,
                                egismoc_delete_run_state,
                                DELETE_STATES);
  /* the print is owned by libfprint during deletion task */
  fpi_ssm_set_data (self->task_ssm, delete_print, NULL);
  fpi_ssm_start (self->task_ssm, egismoc_task_ssm_done);
}

static void
egismoc_enroll_commit_complete_cb (FpDevice *device,
                                   guchar   *buffer_in,
                                   gsize     length_in,
                                   GError   *error)
{
  fp_dbg ("Enroll commit complete callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  FpSdcpDevice *sdcp_device = FP_SDCP_DEVICE (device);

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      fpi_sdcp_device_enroll_commit_complete (sdcp_device, error);
      return;
    }

  fpi_sdcp_device_enroll_commit_complete (sdcp_device, NULL);
  fpi_ssm_next_state (self->task_ssm);
}

static void
egismoc_enroll_commit_cb (FpDevice *device,
                          guchar   *buffer_in,
                          gsize     length_in,
                          GError   *error)
{
  fp_dbg ("Enroll commit callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  FpSdcpDevice *sdcp_device = FP_SDCP_DEVICE (device);

  g_clear_pointer (&self->enrollment_nonce, g_bytes_unref);

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      fpi_sdcp_device_enroll_commit_complete (sdcp_device, error);
      return;
    }

  if (!egismoc_validate_response_suffix (buffer_in,
                                         length_in,
                                         rsp_commit_success_suffix,
                                         rsp_commit_success_suffix_len))
    {
      g_propagate_error (&error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                           "Enrollment was rejected by the device"));
      fpi_ssm_mark_failed (self->task_ssm, error);
      fpi_sdcp_device_enroll_commit_complete (sdcp_device, error);
      return;
    }

  egismoc_exec_cmd (device, cmd_sensor_reset, cmd_sensor_reset_len,
                    NULL, egismoc_enroll_commit_complete_cb);
}

static void
egismoc_enroll_commit (FpSdcpDevice *sdcp_device,
                       GBytes       *id)
{
  fp_dbg ("Enroll commit");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (sdcp_device);
  g_auto(FpiByteWriter) writer = {0};
  g_autoptr(GError) error = NULL;
  const guint8 *new_id;
  gsize new_id_len = 0;
  gsize payload_len = 0;

  fpi_byte_writer_init (&writer);
  if (!fpi_byte_writer_put_data (&writer, cmd_new_print_prefix,
                                 cmd_new_print_prefix_len))
    goto out_fail;

  new_id = g_bytes_get_data (id, &new_id_len);

  if (!fpi_byte_writer_put_data (&writer, new_id, new_id_len))
    goto out_fail;

  payload_len = fpi_byte_writer_get_size (&writer);
  egismoc_exec_cmd (FP_DEVICE (self), fpi_byte_writer_reset_and_get_data (&writer),
                    payload_len, g_free, egismoc_enroll_commit_cb);
  return;

out_fail:
  g_propagate_error (&error, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
  fpi_ssm_mark_failed (self->task_ssm, error);
  fpi_sdcp_device_enroll_commit_complete (sdcp_device, error);
}

static void
egismoc_enroll_status_report (FpDevice    *device,
                              EnrollPrint *enroll_print,
                              EnrollStatus status,
                              GError      *error)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  switch (status)
    {
    case ENROLL_STATUS_DEVICE_FULL:
    case ENROLL_STATUS_DUPLICATE:
      fpi_ssm_mark_failed (self->task_ssm, error);
      break;

    case ENROLL_STATUS_RETRY:
      fpi_device_enroll_progress (device, enroll_print->stage, NULL, error);
      break;

    case ENROLL_STATUS_PARTIAL_OK:
      enroll_print->stage++;
      fp_info ("Partial capture successful. Please touch the sensor again (%d/%d)",
               enroll_print->stage,
               self->max_enroll_stages);
      fpi_device_enroll_progress (device, enroll_print->stage, enroll_print->print, NULL);
      break;

    case ENROLL_STATUS_COMPLETE:
      fp_info ("Enrollment was successful!");
      fpi_device_enroll_complete (device, g_object_ref (enroll_print->print), NULL);
      break;

    default:
      if (error)
        fpi_ssm_mark_failed (self->task_ssm, error);
      else
        fpi_ssm_mark_failed (self->task_ssm,
                             fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                       "Unknown error"));
    }
}

static void
egismoc_read_capture_cb (FpDevice *device,
                         guchar   *buffer_in,
                         gsize     length_in,
                         GError   *error)
{
  fp_dbg ("Read capture callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  EnrollPrint *enroll_print = fpi_ssm_get_data (self->task_ssm);

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  /* Check that the read payload indicates "success" */
  if (egismoc_validate_response_suffix (buffer_in,
                                        length_in,
                                        rsp_read_success_suffix,
                                        rsp_read_success_suffix_len))
    {
      egismoc_enroll_status_report (device, enroll_print,
                                    ENROLL_STATUS_PARTIAL_OK, NULL);
    }
  else
    {
      /* If not success then the sensor can either report "off center" or "sensor is dirty" */

      /* "Off center" */
      if (egismoc_validate_response_suffix (buffer_in,
                                            length_in,
                                            rsp_read_offcenter_suffix,
                                            rsp_read_offcenter_suffix_len))
        error = fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);

      /* "Sensor is dirty" */
      else if (egismoc_validate_response_prefix (buffer_in,
                                                 length_in,
                                                 rsp_read_dirty_prefix,
                                                 rsp_read_dirty_prefix_len))
        error = fpi_device_retry_new_msg (FP_DEVICE_RETRY_REMOVE_FINGER,
                                          "Your device is having trouble recognizing you. "
                                          "Make sure your sensor is clean.");

      else
        error = fpi_device_retry_new_msg (FP_DEVICE_RETRY_REMOVE_FINGER,
                                          "Unknown failure trying to read your finger. "
                                          "Please try again.");

      egismoc_enroll_status_report (device, enroll_print, ENROLL_STATUS_RETRY, error);
    }

  if (enroll_print->stage == self->max_enroll_stages)
    fpi_ssm_next_state (self->task_ssm);
  else
    fpi_ssm_jump_to_state (self->task_ssm, ENROLL_CAPTURE_SENSOR_RESET);
}

static void
egismoc_enroll_starting_cb (FpDevice *device,
                            guchar   *buffer_in,
                            gsize     length_in,
                            GError   *error)
{
  fp_dbg ("Enroll starting callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  g_autofree gchar *enrollment_nonce_hex = NULL;

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  if (!egismoc_validate_response_suffix (buffer_in,
                                         length_in,
                                         rsp_enroll_starting_suffix,
                                         rsp_enroll_starting_suffix_len))
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "Invalid response when starting enrollment"));
      return;
    }

  /* clear and fetch SDCP device enrollment nonce from response */
  g_clear_pointer (&self->enrollment_nonce, g_bytes_unref);
  self->enrollment_nonce = g_bytes_new (buffer_in
                                        + EGISMOC_ENROLL_STARTING_RESPONSE_PREFIX_SIZE,
                                        SDCP_NONCE_SIZE);

  fpi_ssm_next_state (self->task_ssm);
}

static void
egismoc_enroll_check_cb (FpDevice *device,
                         guchar   *buffer_in,
                         gsize     length_in,
                         GError   *error)
{
  fp_dbg ("Enroll check callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  /* Check that the read payload reports "not yet enrolled" */
  if (egismoc_validate_response_suffix (buffer_in,
                                        length_in,
                                        rsp_check_not_yet_enrolled_suffix,
                                        rsp_check_not_yet_enrolled_suffix_len))
    fpi_ssm_next_state (self->task_ssm);
  else
    egismoc_enroll_status_report (device, NULL, ENROLL_STATUS_DUPLICATE,
                                  fpi_device_error_new (FP_DEVICE_ERROR_DATA_DUPLICATE));
}

/*
 * Builds the full "check" payload which includes identifiers for all
 * fingerprints which currently should exist on the storage. This payload is
 * used during both enrollment and verify actions.
 */
static guchar *
egismoc_get_check_cmd (FpDevice *device,
                       gsize    *length_out)
{
  fp_dbg ("Get check command");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  g_auto(FpiByteWriter) writer = {0};
  g_autofree guchar *result = NULL;
  gboolean written = TRUE;

  /*
   * The final command body should contain:
   * 1) hard-coded 00 00
   * 2) 2-byte size indiciator, 20*Number enrolled identifiers plus 9 in form of:
   *    (enrolled_ids->len + 1) * 0x20 + 0x09
   *    Since max prints can be higher than 7 then this goes up to 2 bytes
   *    (e9 + 9 = 109)
   * 3) Hard-coded prefix (cmd_check_prefix)
   * 4) 2-byte size indiciator, 20*Number of enrolled identifiers without plus 9
   *    ((enrolled_ids->len + 1) * 0x20)
   * 5) SDCP Identify nonce (always hard-coded 32 * 0x00 bytes on these devices)
   * 6) All of the currently registered prints in their 32-byte device identifiers
   *    (enrolled_list)
   * 7) Hard-coded suffix (cmd_check_suffix)
   */

  g_assert (self->enrolled_ids);
  const gsize body_length = sizeof (guchar) * self->enrolled_ids->len * SDCP_ENROLLMENT_ID_SIZE;

  /* prefix length can depend on the type */
  const gsize check_prefix_length = (fpi_device_get_driver_data (device) &
                                     EGISMOC_DRIVER_CHECK_PREFIX_TYPE2) ?
                                    cmd_check_prefix_type2_len :
                                    cmd_check_prefix_type1_len;

  /* total_length is the 6 various bytes plus all other prefixes/suffixes and
   * the body payload */
  const gsize total_length = (sizeof (guchar) * 6)
                             + check_prefix_length
                             + SDCP_NONCE_SIZE
                             + body_length
                             + cmd_check_suffix_len;

  /* pre-fill entire payload with 00s */
  fpi_byte_writer_init_with_size (&writer, total_length, TRUE);

  /* start with 00 00 (just move starting offset up by 2) */
  written &= fpi_byte_writer_set_pos (&writer, 2);

  /* Size Counter bytes */
  /* "easiest" way to handle 2-bytes size for counter is to hard-code logic for
   * when we go to the 2nd byte
   * note this will not work in case any model ever supports more than 14 prints
   * (assumed max is 10) */
  if (self->enrolled_ids->len > 6)
    {
      written &= fpi_byte_writer_put_uint8 (&writer, 0x01);
      written &= fpi_byte_writer_put_uint8 (&writer,
                                            ((self->enrolled_ids->len - 7) * 0x20)
                                            + 0x09);
    }
  else
    {
      /* first byte is 0x00, just skip it */
      written &= fpi_byte_writer_change_pos (&writer, 1);
      written &= fpi_byte_writer_put_uint8 (&writer,
                                            ((self->enrolled_ids->len + 1) * 0x20) +
                                            0x09);
    }

  /* command prefix */
  if (fpi_device_get_driver_data (device) & EGISMOC_DRIVER_CHECK_PREFIX_TYPE2)
    written &= fpi_byte_writer_put_data (&writer, cmd_check_prefix_type2,
                                         cmd_check_prefix_type2_len);
  else
    written &= fpi_byte_writer_put_data (&writer, cmd_check_prefix_type1,
                                         cmd_check_prefix_type1_len);

  /* 2-bytes size logic for counter again */
  if (self->enrolled_ids->len > 6)
    {
      written &= fpi_byte_writer_put_uint8 (&writer, 0x01);
      written &= fpi_byte_writer_put_uint8 (&writer,
                                            (self->enrolled_ids->len - 7) * 0x20);
    }
  else
    {
      /* first byte is 0x00, just skip it */
      written &= fpi_byte_writer_change_pos (&writer, 1);
      written &= fpi_byte_writer_put_uint8 (&writer,
                                            (self->enrolled_ids->len + 1) * 0x20);
    }

  /* skip ahead to leave Identify nonce as 00s (always 00s for egismoc devices) */
  written &= fpi_byte_writer_change_pos (&writer, SDCP_NONCE_SIZE);

  /* add each of the enrolled IDs */
  for (guint i = 0; i < self->enrolled_ids->len && written; i++)
    {
      written &= fpi_byte_writer_put_data (&writer,
                                           g_ptr_array_index (self->enrolled_ids, i),
                                           SDCP_ENROLLMENT_ID_SIZE);
    }

  /* command suffix */
  written &= fpi_byte_writer_put_data (&writer, cmd_check_suffix,
                                       cmd_check_suffix_len);
  g_assert (written);

  if (length_out)
    *length_out = total_length;

  return fpi_byte_writer_reset_and_get_data (&writer);
}

static void
egismoc_enroll_run_state (FpiSsm   *ssm,
                          FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  FpSdcpDevice *sdcp_device = FP_SDCP_DEVICE (device);
  EnrollPrint *enroll_print = fpi_ssm_get_data (ssm);
  g_autofree guchar *payload = NULL;
  gsize payload_length = 0;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ENROLL_GET_ENROLLED_IDS:
      /* get enrolled_ids from device for use in check stages below */
      egismoc_exec_cmd (device, cmd_list, cmd_list_len,
                        NULL, egismoc_list_fill_enrolled_ids_cb);
      break;

    case ENROLL_CHECK_ENROLLED_NUM:
      if (self->enrolled_ids->len >= EGISMOC_MAX_ENROLL_NUM)
        {
          egismoc_enroll_status_report (device, enroll_print, ENROLL_STATUS_DEVICE_FULL,
                                        fpi_device_error_new (FP_DEVICE_ERROR_DATA_FULL));
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case ENROLL_SENSOR_RESET:
      egismoc_exec_cmd (device, cmd_sensor_reset, cmd_sensor_reset_len,
                        NULL, egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_SENSOR_ENROLL:
      egismoc_exec_cmd (device, cmd_sensor_enroll, cmd_sensor_enroll_len,
                        NULL, egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_WAIT_FINGER:
      egismoc_wait_finger_on_sensor (device);
      break;

    case ENROLL_SENSOR_CHECK:
      egismoc_exec_cmd (device, cmd_sensor_check, cmd_sensor_check_len,
                        NULL, egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_CHECK:
      payload = egismoc_get_check_cmd (device, &payload_length);
      egismoc_exec_cmd (device, g_steal_pointer (&payload), payload_length,
                        g_free, egismoc_enroll_check_cb);
      break;

    case ENROLL_START:
      egismoc_exec_cmd (device, cmd_enroll_starting, cmd_enroll_starting_len,
                        NULL, egismoc_enroll_starting_cb);
      break;

    case ENROLL_CAPTURE_SENSOR_RESET:
      egismoc_exec_cmd (device, cmd_sensor_reset, cmd_sensor_reset_len,
                        NULL, egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_CAPTURE_SENSOR_START_CAPTURE:
      egismoc_exec_cmd (device, cmd_sensor_start_capture, cmd_sensor_start_capture_len,
                        NULL,
                        egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_CAPTURE_WAIT_FINGER:
      egismoc_wait_finger_on_sensor (device);
      break;

    case ENROLL_CAPTURE_POST_WAIT_FINGER:
      egismoc_exec_cmd (device, cmd_capture_post_wait_finger, cmd_capture_post_wait_finger_len,
                        NULL, egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_CAPTURE_READ_RESPONSE:
      egismoc_exec_cmd (device, cmd_read_capture, cmd_read_capture_len,
                        NULL, egismoc_read_capture_cb);
      break;

    case ENROLL_COMMIT_START:
      egismoc_exec_cmd (device, cmd_commit_starting, cmd_commit_starting_len,
                        NULL, egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_COMMIT:
      g_assert (self->enrollment_nonce);
      fpi_sdcp_device_enroll_commit (sdcp_device, self->enrollment_nonce, NULL);
      break;
    }
}

static void
egismoc_enroll (FpSdcpDevice *sdcp_device)
{
  fp_dbg ("Enroll");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (sdcp_device);
  FpDevice *device = FP_DEVICE (sdcp_device);
  EnrollPrint *enroll_print = g_new0 (EnrollPrint, 1);

  fpi_device_get_enroll_data (device, &enroll_print->print);
  enroll_print->stage = 0;

  g_assert (self->task_ssm == NULL);
  self->task_ssm = fpi_ssm_new (device, egismoc_enroll_run_state, ENROLL_STATES);
  fpi_ssm_set_data (self->task_ssm, g_steal_pointer (&enroll_print), g_free);
  fpi_ssm_start (self->task_ssm, egismoc_task_ssm_done);
}

static void
egismoc_identify_complete_cb (FpDevice *device,
                              guchar   *buffer_in,
                              gsize     length_in,
                              GError   *error)
{
  fp_dbg ("Identify complete callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  FpSdcpDevice *sdcp_device = FP_SDCP_DEVICE (device);
  IdentifyPrint *identify_print = fpi_ssm_get_data (self->task_ssm);

  if (error)
    {
      fpi_device_action_error (device, error);
      goto out;
    }

  fpi_sdcp_device_identify_complete (sdcp_device, identify_print->id, identify_print->mac,
                                     identify_print->error);

  fpi_ssm_next_state (self->task_ssm);

out:
  g_clear_pointer (&identify_print->id, g_bytes_unref);
  g_clear_pointer (&identify_print->mac, g_bytes_unref);
  g_clear_pointer (&identify_print, g_free);
}

static void
egismoc_identify_check_cb (FpDevice *device,
                           guchar   *buffer_in,
                           gsize     length_in,
                           GError   *error)
{
  fp_dbg ("Identify check callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  FpSdcpDevice *sdcp_device = FP_SDCP_DEVICE (device);
  IdentifyPrint *identify_print = fpi_ssm_get_data (self->task_ssm);
  g_autofree guchar *nonce_buf = NULL;
  g_autoptr(GBytes) nonce = NULL;

  g_return_if_fail (identify_print->id == NULL);
  g_return_if_fail (identify_print->mac == NULL);

  if (error)
    {
      fpi_device_action_error (device, error);
      return;
    }

  /* Check that the read payload indicates "match" */
  if (egismoc_validate_response_suffix (buffer_in,
                                        length_in,
                                        rsp_identify_match_suffix,
                                        rsp_identify_match_suffix_len))
    {
      /*
       * egismoc devices always use 00s for the identify nonce, so we should set
       * it here instead of using the default randomly generated nonce
       */
      nonce_buf = g_malloc0 (SDCP_NONCE_SIZE);
      nonce = g_bytes_new (nonce_buf, SDCP_NONCE_SIZE);
      fpi_sdcp_device_set_identify_data (sdcp_device, g_steal_pointer (&nonce));

      /*
         Normally for SDCP the "Authorized Identity" response should be (id,m)
         but on egismoc devices there is a prefix, followed by (m,id) (yes, it
         is backwards), followed by a suffix.
       */
      identify_print->mac = g_bytes_new (buffer_in
                                         + EGISMOC_IDENTIFY_RESPONSE_PREFIX_SIZE,
                                         SDCP_MAC_SIZE);
      identify_print->id = g_bytes_new (buffer_in
                                        + EGISMOC_IDENTIFY_RESPONSE_PREFIX_SIZE
                                        + SDCP_MAC_SIZE,
                                        SDCP_ENROLLMENT_ID_SIZE);
    }
  /* If device was not successfully read (not a valid "not matched") */
  else if (!egismoc_validate_response_suffix (buffer_in,
                                              length_in,
                                              rsp_identify_notmatch_suffix,
                                              rsp_identify_notmatch_suffix_len))
    {
      g_propagate_error (&identify_print->error,
                         fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                   "Unrecognized response from device"));
    }

  egismoc_exec_cmd (device, cmd_sensor_reset, cmd_sensor_reset_len,
                    NULL, egismoc_identify_complete_cb);
}

static void
egismoc_identify_run_state (FpiSsm   *ssm,
                            FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  g_autofree guchar *payload = NULL;
  gsize payload_length = 0;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case IDENTIFY_GET_ENROLLED_IDS:
      /* get enrolled_ids from device for use in check stages below */
      egismoc_exec_cmd (device, cmd_list, cmd_list_len,
                        NULL, egismoc_list_fill_enrolled_ids_cb);
      break;

    case IDENTIFY_CHECK_ENROLLED_NUM:
      if (self->enrolled_ids->len == 0)
        {
          fpi_ssm_mark_failed (g_steal_pointer (&self->task_ssm),
                               fpi_device_error_new (FP_DEVICE_ERROR_DATA_NOT_FOUND));
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case IDENTIFY_SENSOR_RESET:
      egismoc_exec_cmd (device, cmd_sensor_reset, cmd_sensor_reset_len,
                        NULL, egismoc_task_ssm_next_state_cb);
      break;

    case IDENTIFY_SENSOR_IDENTIFY:
      egismoc_exec_cmd (device, cmd_sensor_identify, cmd_sensor_identify_len,
                        NULL, egismoc_task_ssm_next_state_cb);
      break;

    case IDENTIFY_WAIT_FINGER:
      egismoc_wait_finger_on_sensor (device);
      break;

    case IDENTIFY_SENSOR_CHECK:
      egismoc_exec_cmd (device, cmd_sensor_check, cmd_sensor_check_len,
                        NULL, egismoc_task_ssm_next_state_cb);
      break;

    case IDENTIFY_CHECK:
      payload = egismoc_get_check_cmd (device, &payload_length);
      egismoc_exec_cmd (device, g_steal_pointer (&payload), payload_length,
                        g_free, egismoc_identify_check_cb);
      break;
    }
}

static void
egismoc_identify (FpSdcpDevice *sdcp_device)
{
  fp_dbg ("Identify");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (sdcp_device);
  IdentifyPrint *identify_print = g_new0 (IdentifyPrint, 1);

  g_assert (self->task_ssm == NULL);
  self->task_ssm = fpi_ssm_new (FP_DEVICE (sdcp_device),
                                egismoc_identify_run_state,
                                IDENTIFY_STATES);
  fpi_ssm_set_data (self->task_ssm, g_steal_pointer (&identify_print), NULL);
  fpi_ssm_start (self->task_ssm, egismoc_task_ssm_done);
}

/*
 * Validates and uses the SDCP "ConnectResponse" payload to establish a secure
 * device connection which can then be used to generate enrollment IDs and
 * verify identities as per SDCP.
 */
static void
egismoc_connect_cb (FpDevice *device,
                    guchar   *buffer_in,
                    gsize     length_in,
                    GError   *error)
{
  fp_dbg ("SDCP ConnectResponse callback");
  FpSdcpDevice *sdcp_device = FP_SDCP_DEVICE (device);
  g_autoptr(GBytes) device_random = NULL;
  gsize model_certificate_len = 0;
  g_autoptr(FpiSdcpClaim) claim = NULL;
  g_autoptr(GBytes) mac = NULL;
  int pos = EGISMOC_CONNECT_RESPONSE_PREFIX_SIZE;

  if (error)
    {
      fpi_sdcp_device_connect_complete (sdcp_device, NULL, NULL, NULL, error);
      return;
    }

  /* Check that the read payload indicates "success" */
  if (!egismoc_validate_response_suffix (buffer_in,
                                         length_in,
                                         rsp_sdcp_connect_success_suffix,
                                         rsp_sdcp_connect_success_suffix_len))
    {
      fpi_sdcp_device_connect_complete (sdcp_device, NULL, NULL, NULL,
                                        fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                                  "Device responded with failure "
                                                                  "instead of SDCP ConnectResponse"));
      return;
    }

  /* buf len should be at least larger than all required parts (plus a cert) */
  if (length_in <= SDCP_RANDOM_SIZE
      + SDCP_PUBLIC_KEY_SIZE
      + SDCP_PUBLIC_KEY_SIZE
      + SDCP_RANDOM_SIZE
      + SDCP_SIGNATURE_SIZE
      + SDCP_SIGNATURE_SIZE
      + SDCP_MAC_SIZE)
    {
      fpi_sdcp_device_connect_complete (sdcp_device, NULL, NULL, NULL,
                                        fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                                  "Device SDCP ConnectResponse "
                                                                  "was not long enough"));
      return;
    }


  /*
   * Parse ConnectResponse parts; unfortunately these devices return a somewhat
   * non-standard ConnectResponse as there are two bytes indicating cert_m's
   * length which must be handled.
   */
  claim = g_new0 (FpiSdcpClaim, 1);

  /* r_d */
  device_random = g_bytes_new (buffer_in + pos, SDCP_RANDOM_SIZE);
  pos += SDCP_RANDOM_SIZE;

  /* next two bytes are an unsigned short giving the cert_m length */
  model_certificate_len = buffer_in[pos] << 8 | buffer_in[pos + 1];
  pos += 2;

  /* cert_m bytes based on length fetched above */
  claim->model_certificate = g_bytes_new (buffer_in + pos, model_certificate_len);
  pos += model_certificate_len;

  /* pk_d */
  claim->device_public_key = g_bytes_new (buffer_in + pos, SDCP_PUBLIC_KEY_SIZE);
  pos += SDCP_PUBLIC_KEY_SIZE;

  /* pk_f */
  claim->firmware_public_key = g_bytes_new (buffer_in + pos, SDCP_PUBLIC_KEY_SIZE);
  pos += SDCP_PUBLIC_KEY_SIZE;

  /* h_f */
  claim->firmware_hash = g_bytes_new (buffer_in + pos, SDCP_MAC_SIZE);
  pos += SDCP_MAC_SIZE;

  /* s_m */
  claim->model_signature = g_bytes_new (buffer_in + pos, SDCP_SIGNATURE_SIZE);
  pos += SDCP_SIGNATURE_SIZE;

  /* s_d */
  claim->device_signature = g_bytes_new (buffer_in + pos, SDCP_SIGNATURE_SIZE);
  pos += SDCP_SIGNATURE_SIZE;

  /* m */
  mac = g_bytes_new (buffer_in + pos, SDCP_MAC_SIZE);
  pos += SDCP_MAC_SIZE;

  /* Derive SDCP keys and establish secured connection */
  fpi_sdcp_device_connect_complete (sdcp_device, device_random, claim, mac, error);
}

static void
egismoc_connect (FpSdcpDevice *sdcp_device)
{
  fp_dbg ("Connect");
  FpDevice *device = FP_DEVICE (sdcp_device);
  g_auto(FpiByteWriter) writer = {0};
  gboolean written = TRUE;
  g_autoptr(GError) error = NULL;

  g_autoptr(GBytes) host_random = NULL;
  const guchar *host_random_ptr;
  gsize host_random_len = 0;

  g_autoptr(GBytes) host_public_key = NULL;
  const guchar *host_public_key_ptr;
  gsize host_public_key_len = 0;

  fpi_sdcp_device_get_connect_data (sdcp_device, &host_random, &host_public_key);
  if (!host_random || !host_public_key)
    {
      fpi_sdcp_device_connect_complete (sdcp_device, NULL, NULL, NULL,
                                        fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                  "Failed to get SDCP Connect data"));
      return;
    }

  host_random_ptr = g_bytes_get_data (host_random, &host_random_len);
  host_public_key_ptr = g_bytes_get_data (host_public_key, &host_public_key_len);

  const int length = cmd_sdcp_connect_prefix_len
                     + host_random_len
                     + host_public_key_len
                     + cmd_sdcp_connect_suffix_len;

  fpi_byte_writer_init_with_size (&writer, length, TRUE);

  written &= fpi_byte_writer_put_data (&writer, cmd_sdcp_connect_prefix,
                                       cmd_sdcp_connect_prefix_len);

  written &= fpi_byte_writer_put_data (&writer, host_random_ptr,
                                       host_random_len);

  written &= fpi_byte_writer_put_data (&writer, host_public_key_ptr,
                                       host_public_key_len);

  written &= fpi_byte_writer_put_data (&writer, cmd_sdcp_connect_suffix,
                                       cmd_sdcp_connect_suffix_len);

  if (!written)
    {
      fpi_sdcp_device_connect_complete (sdcp_device, NULL, NULL, NULL,
                                        fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                  "Failed to write SDCP Connect payload"));
      return;
    }

  /* Execute the egismoc SDCP "Connect" command */
  egismoc_exec_cmd (device,
                    fpi_byte_writer_reset_and_get_data (&writer), length, g_free,
                    egismoc_connect_cb);
}

static void
egismoc_dev_init_done (FpiSsm   *ssm,
                       FpDevice *device,
                       GError   *error)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  if (error)
    {
      g_usb_device_release_interface (
        fpi_device_get_usb_device (device), 0, 0, NULL);
      egismoc_task_ssm_done (ssm, device, error);
      return;
    }

  egismoc_task_ssm_done (ssm, device, NULL);
  fpi_sdcp_device_open_complete (FP_SDCP_DEVICE (device), NULL);

  self->dev_init_done = TRUE;
}

static void
egismoc_fw_version_cb (FpDevice *device,
                       guchar   *buffer_in,
                       gsize     length_in,
                       GError   *error)
{
  fp_dbg ("Firmware version callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  g_autofree gchar *fw_version = NULL;
  gsize prefix_length;
  guchar *fw_version_start;
  gsize fw_version_length;

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  /* Check that the read payload indicates "success" */
  if (!egismoc_validate_response_suffix (buffer_in,
                                         length_in,
                                         rsp_fw_version_suffix,
                                         rsp_fw_version_suffix_len))
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "Device firmware response "
                                                     "was not valid"));
      return;
    }

  /*
   * FW Version is 12 bytes: a carriage return (0x0d) plus the version string
   * itself. Always skip [the read prefix] + [2 * check bytes] + [3 * 0x00] that
   * come with every payload Then we will also skip the carriage return and take
   * all but the last 2 bytes as the FW Version
   */
  prefix_length = egismoc_read_prefix_len + 2 + 3 + 1;
  fw_version_start = buffer_in + prefix_length;
  fw_version_length = length_in - prefix_length - rsp_fw_version_suffix_len;
  fw_version = g_strndup ((gchar *) fw_version_start, fw_version_length);

  fp_info ("Device firmware version is %s", fw_version);

  fpi_ssm_next_state (self->task_ssm);
}

static void
egismoc_dev_init_handler (FpiSsm   *ssm,
                          FpDevice *device)
{
  g_autoptr(FpiUsbTransfer) transfer = fpi_usb_transfer_new (device);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case DEV_INIT_CONTROL1:
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     32, 0x0000, 4, 16);
      break;

    case DEV_INIT_CONTROL2:
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     32, 0x0000, 4, 40);
      break;

    case DEV_INIT_CONTROL3:
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_STANDARD,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     0, 0x0000, 0, 2);
      break;

    case DEV_INIT_CONTROL4:
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_STANDARD,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     0, 0x0000, 0, 2);
      break;

    case DEV_INIT_CONTROL5:
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     82, 0x0000, 0, 8);
      break;

    case DEV_GET_FW_VERSION:
      egismoc_exec_cmd (device, cmd_fw_version, cmd_fw_version_len,
                        NULL, egismoc_fw_version_cb);
      return;

    default:
      g_assert_not_reached ();
    }

  transfer->ssm = ssm;
  transfer->short_is_error = TRUE;
  fpi_usb_transfer_submit (g_steal_pointer (&transfer),
                           EGISMOC_USB_CONTROL_TIMEOUT,
                           fpi_device_get_cancellable (device),
                           fpi_ssm_usb_transfer_cb,
                           NULL);
}

static void
egismoc_open (FpSdcpDevice *sdcp_device)
{
  fp_dbg ("Opening device");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (sdcp_device);
  FpDevice *device = FP_DEVICE (sdcp_device);
  GError *error = NULL;

  self->interrupt_cancellable = g_cancellable_new ();

  if (!g_usb_device_reset (fpi_device_get_usb_device (device), &error))
    {
      fpi_sdcp_device_open_complete (sdcp_device, error);
      return;
    }

  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (device),
                                     0, 0, &error))
    {
      fpi_sdcp_device_open_complete (sdcp_device, error);
      return;
    }

  if (self->dev_init_done)
    {
      fpi_sdcp_device_open_complete (FP_SDCP_DEVICE (device), NULL);
    }
  else
    {
      g_assert (self->task_ssm == NULL);
      self->task_ssm = fpi_ssm_new (device, egismoc_dev_init_handler, DEV_INIT_STATES);
      fpi_ssm_start (self->task_ssm, egismoc_dev_init_done);
    }
}

static void
egismoc_cancel (FpDevice *device)
{
  fp_dbg ("Cancel");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  g_cancellable_cancel (self->interrupt_cancellable);
  g_clear_object (&self->interrupt_cancellable);
  self->interrupt_cancellable = g_cancellable_new ();

  /* Terminate ongoing action if cancel is called */
  if (self->task_ssm)
    fpi_ssm_mark_failed (self->task_ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                                   "Operation was cancelled"));
}

static void
egismoc_suspend (FpDevice *device)
{
  fp_dbg ("Suspend");

  egismoc_cancel (device);
  g_cancellable_cancel (fpi_device_get_cancellable (device));
  fpi_device_suspend_complete (device, NULL);
}

static void
egismoc_close (FpDevice *device)
{
  fp_dbg ("Closing device");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  GError *error = NULL;

  egismoc_cancel (device);
  g_clear_object (&self->interrupt_cancellable);

  g_usb_device_release_interface (fpi_device_get_usb_device (device),
                                  0, 0, &error);

  /*
   * egismoc_open() unconditionally resets the USB device, which wipes the
   * sensor's negotiated firmware state. Force the init handshake to run
   * again on the next open instead of trusting stale state from before
   * this close (e.g. across a suspend/resume cycle).
   */
  self->dev_init_done = FALSE;

  fpi_device_close_complete (device, error);
}

static void
egismoc_probe (FpDevice *device)
{
  GUsbDevice *usb_dev;
  GError *error = NULL;
  g_autofree gchar *serial = NULL;
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  guint64 driver_data;

  /* Claim usb interface */
  usb_dev = fpi_device_get_usb_device (device);
  if (!g_usb_device_open (usb_dev, &error))
    {
      fp_dbg ("%s g_usb_device_open failed %s", G_STRFUNC, error->message);
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }

  if (!g_usb_device_reset (usb_dev, &error))
    {
      fp_dbg ("%s g_usb_device_reset failed %s", G_STRFUNC, error->message);
      g_usb_device_close (usb_dev, NULL);
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }

  if (!g_usb_device_claim_interface (usb_dev, 0, 0, &error))
    {
      fp_dbg ("%s g_usb_device_claim_interface failed %s", G_STRFUNC, error->message);
      g_usb_device_close (usb_dev, NULL);
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }

  if (g_strcmp0 (g_getenv ("FP_DEVICE_EMULATION"), "1") == 0)
    serial = g_strdup ("emulated-device");
  else
    serial = g_usb_device_get_string_descriptor (usb_dev,
                                                 g_usb_device_get_serial_number_index (usb_dev),
                                                 &error);

  if (error)
    {
      fp_dbg ("%s g_usb_device_get_string_descriptor failed %s", G_STRFUNC, error->message);
      g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (device)),
                                      0, 0, NULL);
      g_usb_device_close (usb_dev, NULL);
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }

  driver_data = fpi_device_get_driver_data (device);
  if (driver_data & EGISMOC_DRIVER_MAX_ENROLL_STAGES_20)
    self->max_enroll_stages = 20;
  else if (driver_data & EGISMOC_DRIVER_MAX_ENROLL_STAGES_15)
    self->max_enroll_stages = 15;
  else
    self->max_enroll_stages = EGISMOC_MAX_ENROLL_STAGES_DEFAULT;

  fpi_device_set_nr_enroll_stages (device, self->max_enroll_stages);

  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (device)), 0, 0, NULL);
  g_usb_device_close (usb_dev, NULL);

  fpi_device_probe_complete (device, serial, NULL, error);
}

static void
fpi_device_egismoc_init (FpiDeviceEgisMoc *self)
{
  G_DEBUG_HERE ();
}

static void
fpi_device_egismoc_class_init (FpiDeviceEgisMocClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpSdcpDeviceClass *sdcp_dev_class = FP_SDCP_DEVICE_CLASS (klass);

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = EGISMOC_DRIVER_FULLNAME;

  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->id_table = egismoc_id_table;
  dev_class->nr_enroll_stages = EGISMOC_MAX_ENROLL_STAGES_DEFAULT;
  /* device should be "always off" unless being used */
  dev_class->temp_hot_seconds = 0;

  sdcp_dev_class->open = egismoc_open;
  sdcp_dev_class->connect = egismoc_connect;
  sdcp_dev_class->list = egismoc_list;
  sdcp_dev_class->enroll = egismoc_enroll;
  sdcp_dev_class->enroll_commit = egismoc_enroll_commit;
  sdcp_dev_class->identify = egismoc_identify;

  dev_class->probe = egismoc_probe;
  dev_class->cancel = egismoc_cancel;
  dev_class->suspend = egismoc_suspend;
  dev_class->close = egismoc_close;
  dev_class->delete = egismoc_delete;
  dev_class->clear_storage = egismoc_clear_storage;

  fpi_device_class_auto_initialize_features (dev_class);
  dev_class->features |= FP_DEVICE_FEATURE_DUPLICATES_CHECK;

  sdcp_dev_class->ignore_device_certificate = FALSE;
  sdcp_dev_class->ignore_device_signatures = FALSE;
}
