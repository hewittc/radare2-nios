project('radare2-nios', 'c',
  version: '0.2.0',
  license: 'LGPL3',
  default_options: ['c_std=gnu99', 'warning_level=1'],
  meson_version: '>=1.10',
)

r_arch_dep = dependency('r_arch')
r_util_dep = dependency('r_util')

plugin_deps = [r_arch_dep, r_util_dep]
plugin_sources = [
  'plugin.c',
  'gnu/cgen-asm.c',
  'gnu/cgen-bitset.c',
  'gnu/cgen-dis.c',
  'gnu/cgen-opc.c',
  'gnu/cpu-nios.c',
  'gnu/nios-asm.c',
  'gnu/nios-desc.c',
  'gnu/nios-dis.c',
  'gnu/nios-ibld.c',
  'gnu/nios-opc.c',
  'gnu/safe-ctype.c'
]

inc_dirs = include_directories('.', 'gnu', 'include')

r2_plugdir = get_option('plugindir')
if r2_plugdir == ''
  r2_plugdir = join_paths(get_option('prefix'), get_option('libdir'), 'radare2', 'plugins')
endif

shared_module('nios',
  plugin_sources,
  dependencies: plugin_deps,
  include_directories: inc_dirs,
  install: true,
  install_dir: r2_plugdir,
  c_args: ['-fPIC'],
  name_prefix: ''
)
