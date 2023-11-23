SPDX-License-Identifier: GPL-2.0-or-later
Copyright 2006 Blender Foundation

set(INC
  .
  include
)

set(INC_SYS

)

set(SRC
# do i actually need to include all of these..?
  include/rlbox.hpp
  include/rlbox_app_pointer.hpp
  include/rlbox_conversion.hpp
  include/rlbox_dylib_sandbox.hpp
  include/rlbox_helpers.hpp
  include/rlbox_noop_sandbox.hpp
  include/rlbox_policy_types.hpp
  include/rlbox_range.hpp
  include/rlbox_sandbox.hpp
  include/rlbox_stdlib.hpp
  include/rlbox_stdlib_polyfill.hpp
  include/rlbox_struct_support.hpp
  include/rlbox_type_traits.hpp
  include/rlbox_types.hpp
  include/rlbox_unwrap.hpp
  include/rlbox_wrapper_traits.hpp
)

set(LIB
)

blender_add_lib(extern_rlbox "${SRC}" "${INC}" "${INC_SYS}" "${LIB}")