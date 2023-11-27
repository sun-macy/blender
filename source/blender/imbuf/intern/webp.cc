/* SPDX-License-Identifier: GPL-2.0-or-later */

/** \file
 * \ingroup imbuf
 */

#ifdef _WIN32
#  include <io.h>
#else
#  include <unistd.h>
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <webp/decode.h>
#include <webp/encode.h>

#include "BLI_fileops.h"
#include "BLI_mmap.h"
#include "BLI_utildefines.h"

#include "IMB_allocimbuf.h"
#include "IMB_colormanagement.h"
#include "IMB_colormanagement_intern.h"
#include "IMB_filetype.h"
#include "IMB_imbuf.h"
#include "IMB_imbuf_types.h"

#include "MEM_guardedalloc.h"

// TODO: add rlbox imports
// TODO: add other misc. rlbox define statements, etc.


bool imb_is_a_webp(const uchar *buf, size_t size)
{
  // TODO: sandbox call
  if (WebPGetInfo(buf, size, nullptr, nullptr)) {
    return true;
  }
  return false;
}

ImBuf *imb_loadwebp(const uchar *mem, size_t size, int flags, char colorspace[IM_MAX_SPACE])
{
  if (!imb_is_a_webp(mem, size)) {
    return nullptr;
  }

  // TODO: create sandbox

  colorspace_set_default_role(colorspace, IM_MAX_SPACE, COLOR_ROLE_DEFAULT_BYTE);

  // TODO: taint this?
  WebPBitstreamFeatures features;
  // TODO: sandbox call
  if (WebPGetFeatures(mem, size, &features) != VP8_STATUS_OK) {
    fprintf(stderr, "WebP: Failed to parse features\n");
    // TODO: destroy sandbox
    return nullptr;
  }

  const int planes = features.has_alpha ? 32 : 24;
  ImBuf *ibuf = IMB_allocImBuf(features.width, features.height, planes, 0);

  if (ibuf == nullptr) {
    fprintf(stderr, "WebP: Failed to allocate image memory\n");
    // TODO: destroy sandbox
    return nullptr;
  }

  if ((flags & IB_test) == 0) {
    ibuf->ftype = IMB_FTYPE_WEBP;
    imb_addrectImBuf(ibuf);
    /* Flip the image during decoding to match Blender. */
    uchar *last_row = (uchar *)(ibuf->rect + (ibuf->y - 1) * ibuf->x);
    // TODO: sandbox call
    if (WebPDecodeRGBAInto(mem, size, last_row, size_t(ibuf->x) * ibuf->y * 4, -4 * ibuf->x) ==
        nullptr)
    {
      fprintf(stderr, "WebP: Failed to decode image\n");
    }
  }

  // TODO: destroy sandbox
  return ibuf;
}

struct ImBuf *imb_load_filepath_thumbnail_webp(const char *filepath,
                                               const int /*flags*/,
                                               const size_t max_thumb_size,
                                               char colorspace[],
                                               size_t *r_width,
                                               size_t *r_height)
{
  const int file = BLI_open(filepath, O_BINARY | O_RDONLY, 0);
  if (file == -1) {
    return nullptr;
  }

  const size_t data_size = BLI_file_descriptor_size(file);

  imb_mmap_lock();
  BLI_mmap_file *mmap_file = BLI_mmap_open(file);
  imb_mmap_unlock();
  close(file);
  if (mmap_file == nullptr) {
    return nullptr;
  }

  const uchar *data = static_cast<const uchar *>(BLI_mmap_get_pointer(mmap_file));

  // TODO: create sandbox

  // TODO: taint this?
  WebPDecoderConfig config;
  // TODO: sandbox call
  if (!data || !WebPInitDecoderConfig(&config) ||
      WebPGetFeatures(data, data_size, &config.input) != VP8_STATUS_OK)
  {
    fprintf(stderr, "WebP: Invalid file\n");
    imb_mmap_lock();
    BLI_mmap_free(mmap_file);
    imb_mmap_unlock();
    // TODO: destroy sandbox
    return nullptr;
  }

  /* Return full size of the image. */
  *r_width = size_t(config.input.width);
  *r_height = size_t(config.input.height);

  const float scale = float(max_thumb_size) / MAX2(config.input.width, config.input.height);
  const int dest_w = MAX2(int(config.input.width * scale), 1);
  const int dest_h = MAX2(int(config.input.height * scale), 1);

  colorspace_set_default_role(colorspace, IM_MAX_SPACE, COLOR_ROLE_DEFAULT_BYTE);
  struct ImBuf *ibuf = IMB_allocImBuf(dest_w, dest_h, 32, IB_rect);
  if (ibuf == nullptr) {
    fprintf(stderr, "WebP: Failed to allocate image memory\n");
    imb_mmap_lock();
    BLI_mmap_free(mmap_file);
    imb_mmap_unlock();
    // TODO: destroy sandbox
    return nullptr;
  }

  config.options.no_fancy_upsampling = 1;
  config.options.use_scaling = 1;
  config.options.scaled_width = dest_w;
  config.options.scaled_height = dest_h;
  config.options.bypass_filtering = 1;
  config.options.use_threads = 0;
  config.options.flip = 1;
  config.output.is_external_memory = 1;
  config.output.colorspace = MODE_RGBA;
  config.output.u.RGBA.rgba = (uint8_t *)ibuf->rect;
  config.output.u.RGBA.stride = 4 * ibuf->x;
  config.output.u.RGBA.size = size_t(config.output.u.RGBA.stride * ibuf->y);

  // TODO: sandbox call
  if (WebPDecode(data, data_size, &config) != VP8_STATUS_OK) {
    fprintf(stderr, "WebP: Failed to decode image\n");
    imb_mmap_lock();
    BLI_mmap_free(mmap_file);
    imb_mmap_unlock();
    // TODO: destroy sandbox
    return nullptr;
  }

  /* Free the output buffer. */
  // TODO: sandbox call
  WebPFreeDecBuffer(&config.output);

  imb_mmap_lock();
  BLI_mmap_free(mmap_file);
  imb_mmap_unlock();

  // TODO: destroy sandbox
  return ibuf;
}

bool imb_savewebp(struct ImBuf *ibuf, const char *filepath, int /*flags*/)
{
  const int bytesperpixel = (ibuf->planes + 7) >> 3;
  uchar *encoded_data, *last_row;
  size_t encoded_data_size;

  // TODO: create sandbox
  if (bytesperpixel == 3) {
    /* We must convert the ImBuf RGBA buffer to RGB as WebP expects a RGB buffer. */
    const size_t num_pixels = ibuf->x * ibuf->y;
    const uint8_t *rgba_rect = (uint8_t *)ibuf->rect;
    uint8_t *rgb_rect = static_cast<uint8_t *>(
        MEM_mallocN(sizeof(uint8_t) * num_pixels * 3, "webp rgb_rect"));
    for (int i = 0; i < num_pixels; i++) {
      rgb_rect[i * 3 + 0] = rgba_rect[i * 4 + 0];
      rgb_rect[i * 3 + 1] = rgba_rect[i * 4 + 1];
      rgb_rect[i * 3 + 2] = rgba_rect[i * 4 + 2];
    }

    last_row = (uchar *)(rgb_rect + (ibuf->y - 1) * ibuf->x * 3);

    if (ibuf->foptions.quality == 100.0f) {
      // TODO: sandbox call
      encoded_data_size = WebPEncodeLosslessRGB(
          last_row, ibuf->x, ibuf->y, -3 * ibuf->x, &encoded_data);
    }
    else {
      // TODO: sandbox call
      encoded_data_size = WebPEncodeRGB(
          last_row, ibuf->x, ibuf->y, -3 * ibuf->x, ibuf->foptions.quality, &encoded_data);
    }
    MEM_freeN(rgb_rect);
  }
  else if (bytesperpixel == 4) {
    last_row = (uchar *)(ibuf->rect + (ibuf->y - 1) * ibuf->x);

    if (ibuf->foptions.quality == 100.0f) {
      // TODO: sandbox call
      encoded_data_size = WebPEncodeLosslessRGBA(
          last_row, ibuf->x, ibuf->y, -4 * ibuf->x, &encoded_data);
    }
    else {
      // TODO: sandbox call
      encoded_data_size = WebPEncodeRGBA(
          last_row, ibuf->x, ibuf->y, -4 * ibuf->x, ibuf->foptions.quality, &encoded_data);
    }
  }
  else {
    fprintf(
        stderr, "WebP: Unsupported bytes per pixel: %d for file: '%s'\n", bytesperpixel, filepath);
    // TODO: destroy sandbox
    return false;
  }

  if (encoded_data != nullptr) {
    FILE *fp = BLI_fopen(filepath, "wb");
    if (!fp) {
      free(encoded_data);
      fprintf(stderr, "WebP: Cannot open file for writing: '%s'\n", filepath);
      return false;
    }
    fwrite(encoded_data, encoded_data_size, 1, fp);
    free(encoded_data);
    fclose(fp);
  }

  // TODO: destroy sandbox
  return true;
}
