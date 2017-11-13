include(GenerateExportHeader)

generate_export_header(hypervisor
  BASE_NAME hypervisor
  EXPORT_MACRO_NAME EXTERN
  EXPORT_FILE_NAME libhv_exports.h
  STATIC_DEFINE SHARED_EXPORTS_BUILT_AS_STATIC)

