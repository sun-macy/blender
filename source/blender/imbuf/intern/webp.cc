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

// ADJ: configure rlbox
#define RLBOX_SINGLE_THREADED_INVOCATIONS
#define RLBOX_USE_STATIC_CALLS() rlbox_noop_sandbox_lookup_symbol

// ADJ: add rlbox imports
#include <rlbox.hpp>
#include <rlbox_noop_sandbox.hpp>

// ADJ: configure to use noop sandbox
  // TODO: change to wasm2c sandbox eventually
RLBOX_DEFINE_BASE_TYPES_FOR(webp, noop);
using sandbox_type_t = rlbox::rlbox_noop_sandbox;

// NOTE: blender community does not like broad imports like this
using namespace rlbox;

// ADJ: define tainted type
template<typename T>
using tainted_webp = rlbox::tainted<T, sandbox_type_t>;

// NOTE: copied from example code. not sure what this does?
#define release_assert(cond, msg) if (!(cond)) { fputs(msg, stderr); abort(); }

// ADJ: struct representation (with janky workaround for unions...?)

  // NOTE: WebPDecoderConfig

#define sandbox_fields_reflection_webp_class_WebPRGBABuffer(f, g, ...)  \
  f(uint8_t*, rgba, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, stride, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(size_t, size, FIELD_NORMAL, ##__VA_ARGS__) g()         

#define sandbox_fields_reflection_webp_class_WebPYUVABuffer(f, g, ...)  \
  f(uint8_t*, y, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(uint8_t*, u, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(uint8_t*, v, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(uint8_t*, a, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, y_stride, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, u_stride, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, v_stride, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, a_stride, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(size_t, y_size, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(size_t, u_size, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(size_t, v_size, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(size_t, a_size, FIELD_NORMAL, ##__VA_ARGS__) g()         

#define sandbox_fields_reflection_webp_class_WebPBitstreamFeatures(f, g, ...)  \
  f(int, width, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, height, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, has_alpha, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, has_animation, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, format, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(uint32_t[5], pad, FIELD_NORMAL, ##__VA_ARGS__) g()         

#define sandbox_fields_reflection_webp_class_WebPRGBAorYUVABuffer(f, g, ...)  \
  f(WebPRGBABuffer, RGBA, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(WebPYUVABuffer, YUVA, FIELD_NORMAL, ##__VA_ARGS__) g()         

#define sandbox_fields_reflection_webp_class_WebPDecBuffer(f, g, ...)  \
  f(WEBP_CSP_MODE, colorspace, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, width, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, height, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, is_external_memory, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(WebPRGBAorYUVABuffer, u, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(uint32_t[4], pad, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(uint8_t*, private_memory, FIELD_NORMAL, ##__VA_ARGS__) g()         

#define sandbox_fields_reflection_webp_class_WebPDecoderOptions(f, g, ...)  \
  f(int, bypass_filtering, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, no_fancy_upsampling, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, use_cropping, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, crop_left, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, crop_top, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, crop_width, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, crop_height, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, use_scaling, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, scaled_width, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, scaled_height, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, use_threads, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, dithering_strength, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, flip, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(int, alpha_dithering_strength, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(uint32_t[5], pad, FIELD_NORMAL, ##__VA_ARGS__) g()         

#define sandbox_fields_reflection_webp_class_WebPDecoderConfig(f, g, ...)  \
  f(WebPBitstreamFeatures, input, FIELD_NORMAL, ##__VA_ARGS__) g()         \
  f(WebPDecBuffer, output, FIELD_NORMAL, ##__VA_ARGS__) g()                \
  f(WebPDecoderOptions, options, FIELD_NORMAL, ##__VA_ARGS__) g()          

#define sandbox_fields_reflection_webp_allClasses(f, ...)            \
  f(WebPRGBABuffer, webp, ##__VA_ARGS__) \
  f(WebPYUVABuffer, webp, ##__VA_ARGS__) \
  f(WebPBitstreamFeatures, webp, ##__VA_ARGS__) \
  f(WebPRGBAorYUVABuffer, webp, ##__VA_ARGS__) \
  f(WebPDecBuffer, webp, ##__VA_ARGS__) \
  f(WebPDecoderOptions, webp, ##__VA_ARGS__) \
  f(WebPDecoderConfig, webp, ##__VA_ARGS__)

rlbox_load_structs_from_library(webp);

// NOTE: inlined this code below so we don't have to figure out parameter types for now
bool imb_is_a_webp(const uchar *buf, size_t size)
{
  if (WebPGetInfo(buf, size, nullptr, nullptr)) {
    return true;
  }
  return false;
}

ImBuf *imb_loadwebp(const uchar *mem, size_t size, int flags, char colorspace[IM_MAX_SPACE])
{
  // ADJ: created sandbox
  rlbox_sandbox<sandbox_type_t> sandbox;
  sandbox.create_sandbox();

  // ADJ: passed necessary parameters into the sandbox
  auto tainted_mem = sandbox.malloc_in_sandbox<uchar>(size);
  rlbox::memcpy(sandbox, tainted_mem, mem, size);
  //auto tainted_size = sandbox.malloc_in_sandbox<size_t>(sizeof(size_t));
  //rlbox::memcpy(sandbox, tainted_size, size, sizeof(size_t));

  // ADJ: sandboxed WebPGetInfo call
  tainted_webp<int> buf_is_a_webp = sandbox_invoke(sandbox, WebPGetInfo, tainted_mem, 
                                                    size, nullptr, nullptr);
  if ((buf_is_a_webp == 0).unverified_safe_because("worst case is early exit")) {
    // ADJ: if buf is not a webp, free all memory and destroy sandbox
    sandbox.free_in_sandbox(tainted_mem);
    //sandbox.free_in_sandbox(tainted_size);
    sandbox.destroy_sandbox();
    return nullptr;
  }

  colorspace_set_default_role(colorspace, IM_MAX_SPACE, COLOR_ROLE_DEFAULT_BYTE);

  // ADJ: tainted this variable
  tainted_webp<WebPBitstreamFeatures*> tainted_features;
  //WebPBitstreamFeatures tainted_features;
  // ADJ: sandboxed WebPGetFeatures call
  tainted_webp<VP8StatusCode> can_parse_features = sandbox_invoke(sandbox, WebPGetFeatures, tainted_mem, 
                                                        size, tainted_features);
  if ((can_parse_features != VP8_STATUS_OK).unverified_safe_because("worst case is early exit")) {
    fprintf(stderr, "WebP: Failed to parse features\n");
    // ADJ: if we can't parse features, free all memory and destroy sandbox
    sandbox.free_in_sandbox(tainted_mem);
    //sandbox.free_in_sandbox(tainted_size);
    sandbox.destroy_sandbox();
    return nullptr;
  }

  const int planes = (tainted_features->has_alpha).unverified_safe_because("just a boolean flag") ? 32 : 24;
  const int ver_width = (tainted_features->width).copy_and_verify([](int value) {
    assert(value > -1);
    return value;
  });
  const int ver_height = (tainted_features->height).copy_and_verify([](int value) {
    assert(value > -1);
    return value;
  });
  ImBuf *ibuf = IMB_allocImBuf(ver_width, ver_height, planes, 0);

  if (ibuf == nullptr) {
    fprintf(stderr, "WebP: Failed to allocate image memory\n");
    // ADJ: if we cannot allocate image memory, free all memory and destroy sandbox
    sandbox.free_in_sandbox(tainted_mem);
    //sandbox.free_in_sandbox(tainted_size);
    sandbox.destroy_sandbox();
    return nullptr;
  }

  if ((flags & IB_test) == 0) {
    ibuf->ftype = IMB_FTYPE_WEBP;
    imb_addrectImBuf(ibuf);

    /* Flip the image during decoding to match Blender. */

    // ADJ: made tainted copy of last_row for use within sandbox
    uchar *last_row = (uchar *)(ibuf->rect + (ibuf->y - 1) * ibuf->x);
      // ibuf->x should be the width of the image? see IMB_imbuf_types.h:164.
    auto tainted_last_row = sandbox.malloc_in_sandbox<uchar>(ibuf->x);
    rlbox::memcpy(sandbox, tainted_last_row, last_row, ibuf->x);

    // ADJ: sandboxed WebPDecodeRGBAInto call
    auto tainted_decode_rgba_into = sandbox_invoke(sandbox, WebPDecodeRGBAInto, 
                                        tainted_mem, size, tainted_last_row, 
                                        size_t(ibuf->x) * ibuf->y * 4, -4 * ibuf->x);
    
    std::unique_ptr<unsigned char> wrapped_decode_rgba_into 
                      = tainted_decode_rgba_into.copy_and_verify([](std::unique_ptr<unsigned char> addr){
                                                                  assert(addr != nullptr);
                                                                  return addr;
                                                                });

    uchar* decode_rgba_into = wrapped_decode_rgba_into.get();

    if(decode_rgba_into == nullptr)
    {
      fprintf(stderr, "WebP: Failed to decode image\n");
    }

    // ADJ: free sandbox memory before we leave its context
    sandbox.free_in_sandbox(tainted_last_row);
  }

  // ADJ: free all memory, destroy sandbox
  sandbox.free_in_sandbox(tainted_mem);
  //sandbox.free_in_sandbox(tainted_size);
  sandbox.destroy_sandbox();
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

  if (!data) {
    fprintf(stderr, "WebP: Invalid file\n");
    imb_mmap_lock();
    BLI_mmap_free(mmap_file);
    imb_mmap_unlock();
    return nullptr;
  }

  // ADJ: created sandbox
  rlbox_sandbox<sandbox_type_t> sandbox;
  sandbox.create_sandbox();

  // ADJ: passed necessary data into the sandbox
  auto tainted_data = sandbox.malloc_in_sandbox<uchar>(data_size);
  rlbox::memcpy(sandbox, tainted_data, data, data_size);

  // ADJ: tainted result
  tainted_webp<WebPDecoderConfig*> tainted_config = sandbox.malloc_in_sandbox<WebPDecoderConfig>(sizeof(WebPDecoderConfig));
  // ADJ: sandboxed calls
  tainted_webp<int> can_obtain_config = sandbox_invoke(sandbox, WebPInitDecoderConfig, tainted_config);

  tainted_webp<WebPBitstreamFeatures*> tainted_config_input = sandbox_reinterpret_cast<WebPBitstreamFeatures*>(tainted_config);

  tainted_webp<VP8StatusCode> can_get_features = sandbox_invoke(sandbox, WebPGetFeatures, tainted_data, data_size, tainted_config_input);
  if ((can_obtain_config == 0).unverified_safe_because("worst case is early exit") 
        || (can_get_features != VP8_STATUS_OK).unverified_safe_because("worst case is early exit"))
  {
    fprintf(stderr, "WebP: Invalid file\n");
    imb_mmap_lock();
    BLI_mmap_free(mmap_file);
    imb_mmap_unlock();
    // ADJ: destroyed sandbox, freed memory
    sandbox.free_in_sandbox(tainted_data);
    sandbox.free_in_sandbox(tainted_config);
    sandbox.destroy_sandbox();
    return nullptr;
  }

  /* Return full size of the image. */
  // ADJ: verify config.input.width and config.input.height before allowing assignment
  *r_width = size_t((tainted_config->input.width).unverified_safe_because("any width is fine"));
  *r_height = size_t((tainted_config->input.height).unverified_safe_because("any height is fine"));

  const float scale = float(max_thumb_size) / MAX2(*r_width, *r_height);
  const int dest_w = MAX2(int(*r_width * scale), 1);
  const int dest_h = MAX2(int(*r_height * scale), 1);

  colorspace_set_default_role(colorspace, IM_MAX_SPACE, COLOR_ROLE_DEFAULT_BYTE);
  struct ImBuf *ibuf = IMB_allocImBuf(dest_w, dest_h, 32, IB_rect);
  if (ibuf == nullptr) {
    fprintf(stderr, "WebP: Failed to allocate image memory\n");
    imb_mmap_lock();
    BLI_mmap_free(mmap_file);
    imb_mmap_unlock();
    // ADJ: destroyed sandbox, freed memory
    sandbox.free_in_sandbox(tainted_data);
    sandbox.free_in_sandbox(tainted_config);
    sandbox.destroy_sandbox();
    return nullptr;
  }

  // ADJ: modify tainted config (i assume write-only is fine???)
  tainted_config->options.no_fancy_upsampling = 1;
  tainted_config->options.use_scaling = 1;
  tainted_config->options.scaled_width = dest_w;
  tainted_config->options.scaled_height = dest_h;
  tainted_config->options.bypass_filtering = 1;
  tainted_config->options.use_threads = 0;
  tainted_config->options.flip = 1;
  tainted_config->output.is_external_memory = 1;
  tainted_config->output.colorspace = MODE_RGBA;

  //tainted_config->output.u.RGBA.rgba = (uint8_t *)ibuf->rect;
  tainted_config->output.u.RGBA.rgba = sandbox.malloc_in_sandbox<uint8_t>(sizeof(uint8_t));
  rlbox::memcpy(sandbox, &(tainted_config->output.u.RGBA.rgba), (uint8_t*) ibuf->rect, sizeof(uint8_t));

  tainted_config->output.u.RGBA.stride = 4 * ibuf->x;
  int stride = (tainted_config->output.u.RGBA.stride).copy_and_verify([](int value) {
    assert(value > -1);
    return value;
  });
  tainted_config->output.u.RGBA.size = size_t(stride * ibuf->y);

  // ADJ: sandboxed call
  tainted_webp<VP8StatusCode> decode_is_okay = sandbox_invoke(sandbox, WebPDecode, tainted_data, data_size, tainted_config);
  if ((decode_is_okay != VP8_STATUS_OK).unverified_safe_because("worst case is early exit")) {
    fprintf(stderr, "WebP: Failed to decode image\n");
    imb_mmap_lock();
    BLI_mmap_free(mmap_file);
    imb_mmap_unlock();
    // ADJ: destroyed sandbox, freed memory
    sandbox.free_in_sandbox(tainted_data);
    sandbox.free_in_sandbox(tainted_config);
    sandbox.destroy_sandbox();
    return nullptr;
  }

  /* Free the output buffer. */
  // ADJ: sandboxed call
  tainted_webp<WebPDecBuffer*> tainted_config_output = sandbox_reinterpret_cast<WebPDecBuffer*>(sandbox_reinterpret_cast<char*>(tainted_config) + sizeof(WebPBitstreamFeatures));
  sandbox_invoke(sandbox, WebPFreeDecBuffer, tainted_config_output);

  imb_mmap_lock();
  BLI_mmap_free(mmap_file);
  imb_mmap_unlock();

  // ADJ: destroyed sandbox, freed memory
  sandbox.free_in_sandbox(tainted_data);
  sandbox.free_in_sandbox(tainted_config);
  sandbox.destroy_sandbox();
  return ibuf;
}

bool imb_savewebp(struct ImBuf *ibuf, const char *filepath, int /*flags*/)
{
  const int bytesperpixel = (ibuf->planes + 7) >> 3;
  uchar *encoded_data, *last_row;
  size_t encoded_data_size;

  // ADJ: created sandbox
  rlbox_sandbox<sandbox_type_t> sandbox;
  sandbox.create_sandbox();

  // ADJ: passed necessary data into the sandbox
  // tainted_webp<size_t> encoded_data_size;

  tainted_webp<uchar**> tainted_data = sandbox.malloc_in_sandbox<uchar*>(sizeof(uchar*));

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

    auto tainted_last_row = sandbox.malloc_in_sandbox<uchar>(ibuf->x);
    rlbox::memcpy(sandbox, tainted_last_row, last_row, ibuf->x);

    if (ibuf->foptions.quality == 100.0f) {
      // NOTE:
      // last_row is a uchar pointer - taint this
      // ibuf->x and ibuf->y are ints
      // -3 * ibuf->x is still an int
      // &encoded_data is the address of encoded_data - taint this
      // ibuf->foptions.quality is a char
      // for verifying encoded data size, max size of a webp file is pow(2,32) - 10 bytes according
      // to webp convention

      // ADJ: sandboxed WebPEncodeLosslessRGB call
      encoded_data_size = sandbox_invoke(sandbox,
                                         WebPEncodeLosslessRGB,
                                         tainted_last_row,
                                         ibuf->x,
                                         ibuf->y,
                                         -3 * ibuf->x,
                                         tainted_data)
                              .copy_and_verify([](unsigned ret) {
                                assert(ret <= pow(2, 32) - 10);
                                return ret;
                              });
      ;
    }
    else {
      // ADJ: sandboxed WebPEncodeRGB call
      encoded_data_size = sandbox_invoke(sandbox,
                                         WebPEncodeRGB,
                                         tainted_last_row,
                                         ibuf->x,
                                         ibuf->y,
                                         -3 * ibuf->x,
                                         ibuf->foptions.quality,
                                         tainted_data)
                              .copy_and_verify([](unsigned ret) {
                                assert(ret <= pow(2, 32) - 10);
                                return ret;
                              });
      ;
    }
    MEM_freeN(rgb_rect);
    sandbox.free_in_sandbox(tainted_last_row);
  }
  else if (bytesperpixel == 4) {
    last_row = (uchar *)(ibuf->rect + (ibuf->y - 1) * ibuf->x);

    auto tainted_last_row = sandbox.malloc_in_sandbox<uchar>(ibuf->x);
    rlbox::memcpy(sandbox, tainted_last_row, last_row, ibuf->x);

    if (ibuf->foptions.quality == 100.0f) {
      // ADJ: sandboxed WebPEncodeLosslessRGBA call
      encoded_data_size = sandbox_invoke(sandbox,
                                         WebPEncodeLosslessRGBA,
                                         tainted_last_row,
                                         ibuf->x,
                                         ibuf->y,
                                         -4 * ibuf->x,
                                         tainted_data)
                              .copy_and_verify([](unsigned ret) {
                                assert(ret <= pow(2, 32) - 10);
                                return ret;
                              });
    }
    else {
      // ADJ: sandboxed WebPEncodeRGBA call
      encoded_data_size = sandbox_invoke(sandbox,
                                         WebPEncodeRGBA,
                                         tainted_last_row,
                                         ibuf->x,
                                         ibuf->y,
                                         -4 * ibuf->x,
                                         ibuf->foptions.quality,
                                         tainted_data)
                              .copy_and_verify([](unsigned ret) {
                                //printf("Encoding Lossy RGB... encoded data size = %d\n", ret);
                                return ret <= pow(2, 32) - 10;
                              });
    }
    sandbox.free_in_sandbox(tainted_last_row);
  }
  else {
    fprintf(
        stderr, "WebP: Unsupported bytes per pixel: %d for file: '%s'\n", bytesperpixel, filepath);
    // ADJ: destroy sandbox, free tainted data
    sandbox.free_in_sandbox(tainted_data);
    sandbox.destroy_sandbox();
    return false;
  }

  // ADJ: verify and free tainted types

  std::unique_ptr<unsigned char> wrapped_verified_data_ptr;

  wrapped_verified_data_ptr = (*tainted_data).copy_and_verify([] (std::unique_ptr<unsigned char> addr) {
    assert(addr != nullptr);
    return addr;
  });

  uchar* verified_data_ptr = wrapped_verified_data_ptr.get();
  encoded_data = (uchar*) malloc(encoded_data_size);
  memcpy(encoded_data, verified_data_ptr, encoded_data_size);
  sandbox.free_in_sandbox(tainted_data);

  if (encoded_data != nullptr)
  {
    FILE *fp = BLI_fopen(filepath, "wb");
    if (!fp) {
      free(encoded_data);
      fprintf(stderr, "WebP: Cannot open file for writing: '%s'\n", filepath);
      // ADJ: destroy sandbox
      sandbox.destroy_sandbox();
      return false;
    }
    fwrite(encoded_data, encoded_data_size, 1, fp);
    free(encoded_data);
    fclose(fp);
  }

  // ADJ: destroy sandbox
  sandbox.destroy_sandbox();
  return true;
}
