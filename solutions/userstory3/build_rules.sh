#!/bin/bash

 set -e

PROJECT_ROOT='/home/black/WS/Group17'   # go to group 17
ZAP_JAR_NAME='zap-D-2020-11-08.jar'
OUTPUT_JAR_NAME='rules.jar'


cd "${PROJECT_ROOT}"/zap-addons/addOns/reportingproxy/src/main/java
javac -cp "${PROJECT_ROOT}"/zaproxy/zap/build/libs/"${ZAP_JAR_NAME}":"${PROJECT_ROOT}"/zap-addons/addOns/reportingproxy/build/libs/reportingproxy-1.jar org/zaproxy/zap/extension/reportingproxy/rules/*.java
jar cMf "${OUTPUT_JAR_NAME}" org/zaproxy/zap/extension/reportingproxy/rules/*.class
mv "${OUTPUT_JAR_NAME}" "${PROJECT_ROOT}"/solutions/userstory3/"${OUTPUT_JAR_NAME}"

