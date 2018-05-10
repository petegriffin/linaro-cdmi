/*
 * Copyright 2014 Fraunhofer FOKUS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <iostream>
#include <sstream>
#include <string.h>

#include "imp.h"
#include <cdmi-log.h>

using namespace std;

BEGIN_NAMESPACE_OCDM()

uint32_t CMediaKeys::s_sessionCnt = 10;

CMediaKeys::CMediaKeys() {}

CMediaKeys::~CMediaKeys(void) {}

bool CMediaKeys::IsTypeSupported(
    const char *f_pwszMimeType,
    const char *f_pwszKeySystem) const {
  bool isSupported = false;
  if (f_pwszKeySystem)
      if (strcmp(f_pwszKeySystem, "org.w3.clearkey") == 0 || strcmp(f_pwszKeySystem, "org.chromium.externalclearkey") == 0)
          isSupported = true;

  return isSupported;
}

const char * CMediaKeys::CreateSessionId() {
  const char *tmp;
  stringstream strs;
  strs << s_sessionCnt;
  string tmp_str = strs.str();
  tmp = tmp_str.c_str();

  char *buffer = new char[tmp_str.length()]();
  strcpy(buffer, tmp);

  s_sessionCnt += 1;

  return const_cast<char*>(buffer);
}

CDMi_RESULT CMediaKeys::CreateMediaKeySession(
    const char *f_pwszMimeType,
    const uint8_t *f_pbInitData,
    uint32_t f_cbInitData,
    const uint8_t *f_pbCDMData,
    uint32_t f_cbCDMData,
    IMediaKeySession **f_ppiMediaKeySession) {
  CDMI_DLOG() << "#CMediaKeys::CreateMediaKeySession" << endl;

  CDMi_RESULT dr;
  CMediaKeySession *poMediaKeySession = NULL;

  *f_ppiMediaKeySession = NULL;

  poMediaKeySession = new CMediaKeySession(CMediaKeys::CreateSessionId());

  dr = poMediaKeySession->Init(f_pbInitData,
      f_cbInitData,
      f_pbCDMData,
      f_cbCDMData);

  *f_ppiMediaKeySession = static_cast<IMediaKeySession *>(poMediaKeySession);

  if (dr != CDMi_SUCCESS) {
    delete poMediaKeySession;
  }
  return dr;
}

CDMi_RESULT CMediaKeys::DestroyMediaKeySession(
    IMediaKeySession *f_piMediaKeySession) {
  CDMi_RESULT dr = CDMi_SUCCESS;

  delete f_piMediaKeySession;

  return dr;
}

CDMi_RESULT CreateMediaKeys(IMediaKeys **f_ppiMediaKeys) {
  CMediaKeys *pMediaKeys = NULL;
  *f_ppiMediaKeys = NULL;

  pMediaKeys = new CMediaKeys();
  *f_ppiMediaKeys = static_cast<IMediaKeys *>(pMediaKeys);

  return CDMi_SUCCESS;
}

CDMi_RESULT DestroyMediaKeys(IMediaKeys *f_piMediaKeys) {
  CDMi_RESULT dr = CDMi_SUCCESS;

  delete f_piMediaKeys;

  return dr;
}

END_NAMESPACE_OCDM()
