void FUN_140008fd0(int param_1)

{
  wchar_t wVar1;
  LSTATUS LVar2;
  longlong lVar3;
  HANDLE hObject;
  longlong lVar4;
  code *lpStartAddress;
  undefined4 *lpParameter;
  bool bVar5;
  undefined1 auStackY_48 [32];
  HKEY local_18;
  ulonglong local_10;
  
  local_10 = DAT_14007a060 ^ (ulonglong)auStackY_48;
  local_18 = (HKEY)0x0;
  LVar2 = RegOpenKeyExW((HKEY)0xffffffff80000002,L"Software\\Bitdefender\\InternalCrashEnabled",0,
                        0x20019,&local_18);
  if (LVar2 != 0) goto LAB_14000914b;
  if (local_18 != (HKEY)0x0) {
    RegCloseKey(local_18);
  }
  if (param_1 < 0) goto LAB_14000914b;
                    /* WARNING: Load size is inaccurate */
  if ((*(int *)(*ThreadLocalStoragePointer + 4) < DAT_14007d608) &&
     (_Init_thread_header(&DAT_14007d608), DAT_14007d608 == -1)) {
    DAT_14007d60c = param_1;
    _Init_thread_footer(&DAT_14007d608);
  }
  lVar4 = 0;
  do {
    lVar3 = lVar4 * 2;
    lVar4 = lVar4 + 1;
    if (*(short *)(DAT_14007d600 + lVar3) != *(short *)(&UNK_14006ad7e + lVar4 * 2)) {
      lVar4 = 0;
      goto LAB_1400090d0;
    }
  } while (lVar4 != 8);
  lpStartAddress = FUN_140008d20;
  goto LAB_1400090fd;
  while (lVar4 = lVar3, lVar3 != 8) {
LAB_1400090d0:
    wVar1 = *(wchar_t *)(DAT_14007d600 + lVar4 * 2);
    lVar3 = lVar4 + 1;
    bVar5 = wVar1 == L"crash#"[lVar4 + 7];
    if (!bVar5) goto LAB_1400090eb;
  }
  bVar5 = wVar1 == u_abort__14006ad92[6];
LAB_1400090eb:
  lpStartAddress = FUN_140008d70;
  if (bVar5) {
    lpStartAddress = FUN_140008d50;
  }
LAB_1400090fd:
  lpParameter = (undefined4 *)0x0;
  if (DAT_14007d60c != 0) {
    lpParameter = &DAT_14007d60c;
  }
  hObject = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,lpStartAddress,lpParameter,0,(LPDWORD)0x0);
  if (hObject != (HANDLE)0x0) {
    CloseHandle(hObject);
  }
LAB_14000914b:
  FUN_14002f160(local_10 ^ (ulonglong)auStackY_48);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140009170 @ 140009170