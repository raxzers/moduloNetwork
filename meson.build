project(
  'net_trace',
  ['c', 'cpp'],
  default_options: [
    'warning_level=3',
    'optimization=2',
    'buildtype=debug'
  ]
)

libbpf_inc = get_option('libbpf_include_dir')
libbpf_lib = get_option('libbpf_lib_dir')

subdir('src')
