# ----------------------------
# Compiladores / programas
# ----------------------------
clang = find_program('clang', required: true)
bpftool = find_program('bpftool', required: true)
cxx = meson.get_compiler('cpp')

# ----------------------------
# Directorios de libbpf (definidos en meson_options.txt)
# ----------------------------
libbpf_inc = get_option('libbpf_include_dir')
libbpf_lib = get_option('libbpf_lib_dir')

libbpf = cxx.find_library('bpf', dirs: libbpf_lib, required: true)

# ----------------------------
# Include directories
# ----------------------------
inc = include_directories(
  '.',               # src/ + build/src automáticamente
  libbpf_inc / 'bpf' # headers de libbpf
)

# ----------------------------
# vmlinux.h (archivo generado)
# ----------------------------
vmlinux_h = custom_target(
  'vmlinux_h',
  output: 'vmlinux.h',  # nombre del archivo, pero la ruta se especifica en el comando
  command: [
    'sh', '-c',
    'bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../src/vmlinux.h'
  ],
  build_always: true
)



# ----------------------------
# Compilación BPF object
# ----------------------------
bpf_obj = custom_target(
  'net_trace_bpf',
  input: 'net_trace.bpf.c',
  output: 'net_trace.bpf.o',
  command: [
    clang,
    '-target', 'bpf',
    '-D__TARGET_ARCH_x86',
    '-O2', '-g',
    '-I', meson.current_source_dir(),        # para net_event.h
    '-I', meson.current_build_dir() / 'src', # para vmlinux.h generado
    '-c', '@INPUT@',
    '-o', '@OUTPUT@'
  ],
  depends: vmlinux_h
)

# ----------------------------
# Skeleton
# ----------------------------
skel_h = custom_target(
  'net_trace_skel',
  input: bpf_obj,
  output: 'net_trace.skel.h',
  command: ['bpftool', 'gen', 'skeleton', '@INPUT@'],
  capture: true
)

# ----------------------------
# Ejecutable user-space
# ----------------------------
exe =executable(
  'net_trace',
  [
    'net_trace.cpp',
    skel_h  # skeleton como fuente para dependencias automáticas
  ],
  include_directories: inc,
  dependencies: libbpf
)


# ----------------------------
# Targets de ejecución
# ----------------------------
run_events = run_target(
  'run_events',
  command: ['sudo', exe, 'mode=events'],
  depends: exe
)

run_bandwidth = run_target(
  'run_bandwidth',
  command: ['sudo', exe, 'mode=bandwidth'],
  depends: exe
)