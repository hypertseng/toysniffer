cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

project(toysniffer)

#### Qt5
# find_package( Qt5Core REQUIRED )
# find_package( Qt5Widgets REQUIRED )
# find_package( Qt5Gui REQUIRED )
# find_package( Qt5OpenGL REQUIRED )
# find_package( Qt5Multimedia REQUIRED )
# find_package( Qt5WebKitWidgets REQUIRED )
# find_package( Qt5Xml REQUIRED )
# set( CMAKE_AUTOMOC ON )  # to automoc remove the need to wrap by hand
# find_package(Qt5 COMPONENTS Widgets REQUIRED)
# find_package(Pcap REQUIRED)

# include_directories(${PCAP_INCLUDE_DIRS})

# add_executable(toysniffer
#     main.cpp
#     gui/mainwindow.ui
#     gui/mainwindow.cpp
#     gui/mainwindow.h
#     capture/capture.cpp
#     capture/capture.h
#     parse/parser.cpp
#     parse/parser.h
#     models/packetmodel.cpp
#     models/packetmodel.h
#     utils/utils.cpp
#     utils/utils.h
# )

# target_link_libraries(toysniffer Qt5::Widgets ${PCAP_LIBRARIES})