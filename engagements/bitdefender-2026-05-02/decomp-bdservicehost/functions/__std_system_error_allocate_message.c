ulonglong __std_system_error_allocate_message(DWORD param_1,longlong *param_2)

{
  DWORD DVar1;
  byte *pbVar2;
  ulonglong uVar3;
  
  DVar1 = FormatMessageA(0x1300,(LPCVOID)0x0,param_1,0,(LPSTR)param_2,0,(va_list *)0x0);
  uVar3 = (ulonglong)DVar1;
  if (DVar1 != 0) {
    pbVar2 = (byte *)(*param_2 + -1 + uVar3);
    do {
      if ((&DAT_14005bc30)[*pbVar2] == '\0') {
        return uVar3;
      }
      pbVar2 = pbVar2 + -1;
      uVar3 = uVar3 - 1;
    } while (uVar3 != 0);
  }
  return uVar3;
}


// FUNCTION_END

// FUNCTION_START: LocalFree @ 14002d7c8