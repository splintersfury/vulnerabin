LPWSTR FUN_1400060a0(LPWSTR param_1)

{
  DWORD DVar1;
  DWORD DVar2;
  LPWSTR lpFilename;
  undefined8 local_30 [5];
  
  param_1[0] = L'\0';
  param_1[1] = L'\0';
  param_1[2] = L'\0';
  param_1[3] = L'\0';
  param_1[8] = L'\0';
  param_1[9] = L'\0';
  param_1[10] = L'\0';
  param_1[0xb] = L'\0';
  param_1[0xc] = L'\a';
  param_1[0xd] = L'\0';
  param_1[0xe] = L'\0';
  param_1[0xf] = L'\0';
  *param_1 = L'\0';
  FUN_1400101a0((longlong *)param_1,0x7fff,0);
  lpFilename = param_1;
  if (7 < *(ulonglong *)(param_1 + 0xc)) {
    lpFilename = *(LPWSTR *)param_1;
  }
  DVar1 = GetModuleFileNameW((HMODULE)0x0,lpFilename,0x7fff);
  if (DVar1 != 0) {
    if (DVar1 == 0x7fff) {
      DVar2 = GetLastError();
      if (DVar2 != 0) {
        FUN_140003730(local_30,DVar2);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(local_30,(ThrowInfo *)&DAT_140077a60);
      }
    }
    FUN_14000e410((undefined8 *)param_1,(ulonglong)DVar1,0);
    FUN_14000e4b0((longlong *)param_1);
    return param_1;
  }
  FUN_1400036f0(local_30,(undefined8 *)"GetModuleFileName failed");
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_30,(ThrowInfo *)&DAT_140077a60);
}


// FUNCTION_END

// FUNCTION_START: FUN_140006180 @ 140006180