set( _headerfu_supported_components
  argfu
  httpfu
  inifu
  sslfu
  strfu
  structfu
  sysfu
)

foreach( _comp ${headerfu_FIND_COMPONENTS} )
  if( NOT ";${_headerfu_supported_components};" MATCHES ";${_comp};" )
    set( headerfu_FOUND False )
    set( headerfu_NOT_FOUND_MESSAGE "Unsupported component: ${_comp}" )
    break()
  endif()

  add_library( ${_comp} INTERFACE )
  target_include_directories( ${_comp} INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/include
  )

  if( ${_comp} STREQUAL "sslfu" )
    find_package( OpenSSL 1.1.1 REQUIRED )
  endif()
endforeach()
