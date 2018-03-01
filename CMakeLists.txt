cmake_minimum_required(VERSION 2.8)
option(USE_OBJECT_MQTT_PLATFORM_LWIP_LIBRARY "Build MQTT platform lwip object library." ON)
option(USE_OBJECT_MQTT_PLATFORM_FREERTOS_LIBRARY "Build MQTT platform freertos object library." ON)
option(USE_OBJECT_MQTT_PLATFORM_MBEDTLS_LIBRARY "Build MQTT server object library." OFF)

if(USE_OBJECT_MQTT_PLATFORM_FREERTOS_LIBRARY)
    add_library(paho-mqtt-freertos-object OBJECT    freertos/Thread.c
                                                    freertos/Timer.c
                                                    Network.c)
    target_include_directories(paho-mqtt-freertos-object PRIVATE ${CMAKE_CURRENT_LIST_DIR})
endif(USE_OBJECT_MQTT_PLATFORM_FREERTOS_LIBRARY)

if(USE_OBJECT_MQTT_PLATFORM_LWIP_LIBRARY)
    add_library(paho-mqtt-lwip-object OBJECT        lwip/NetworkLWIP.c)
    target_include_directories(paho-mqtt-lwip-object PRIVATE ${CMAKE_CURRENT_LIST_DIR})
endif(USE_OBJECT_MQTT_PLATFORM_LWIP_LIBRARY)

if(USE_OBJECT_MQTT_PLATFORM_MBEDTLS_LIBRARY)
    add_library(paho-mqtt-mbedtls-object OBJECT     mbedtls/NetworkTLS.c)
    target_include_directories(paho-mqtt-mbedtls-object PRIVATE ${CMAKE_CURRENT_LIST_DIR})
endif(USE_OBJECT_MQTT_PLATFORM_MBEDTLS_LIBRARY)
