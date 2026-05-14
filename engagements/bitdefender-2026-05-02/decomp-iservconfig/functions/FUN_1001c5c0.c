void __thiscall FUN_1001c5c0(void *this,undefined4 param_1,LPCWSTR param_2)

{
  code *pcVar1;
  uint cbMultiByte;
  DWORD DVar2;
  LPSTR ****pppppCVar3;
  int iVar4;
  LPSTR pCVar5;
  DWORD *in_stack_00000018;
  uint uStack_60;
  LPSTR ***local_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  undefined4 local_34;
  uint uStack_30;
  uint local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004f84d;
  local_1c = ExceptionList;
  uStack_60 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = (undefined1 *)&uStack_60;
  ExceptionList = &local_1c;
  local_2c = uStack_60;
  cbMultiByte = WideCharToMultiByte(0xfde9,0,param_2,-1,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
  if ((int)cbMultiByte < 0) {
    DVar2 = GetLastError();
  }
  else if ((cbMultiByte != 0) || (DVar2 = GetLastError(), DVar2 == 0)) {
    *in_stack_00000018 = 0;
    in_stack_00000018[1] = (DWORD)&PTR_vftable_10069aa8;
    if (cbMultiByte == 0) goto LAB_1001c666;
    local_34 = 0;
    uStack_30 = 0xf;
    local_44 = (LPSTR ***)0x0;
    local_14 = 1;
    FUN_10005410(&local_44,cbMultiByte,'\0');
    pppppCVar3 = &local_44;
    if (0xf < uStack_30) {
      pppppCVar3 = (LPSTR ****)local_44;
    }
    iVar4 = WideCharToMultiByte(0xfde9,0,param_2,-1,(LPSTR)pppppCVar3,cbMultiByte,(LPCSTR)0x0,
                                (LPBOOL)0x0);
    if (iVar4 < 0) {
      DVar2 = GetLastError();
      *in_stack_00000018 = DVar2;
      in_stack_00000018[1] = (DWORD)&PTR_vftable_10069ab8;
      *(undefined4 *)this = 0;
      *(undefined4 *)((int)this + 0x10) = 0;
      *(undefined4 *)((int)this + 0x14) = 0xf;
      *(undefined1 *)this = 0;
      if (uStack_30 < 0x10) goto LAB_1001c739;
      pppppCVar3 = (LPSTR ****)local_44;
      if (0xfff < uStack_30 + 1) {
        pppppCVar3 = (LPSTR ****)local_44[-1];
        pCVar5 = (LPSTR)((int)local_44 + (-4 - (int)pppppCVar3));
joined_r0x1001c790:
        if ((LPSTR)0x1f < pCVar5) {
          FUN_10032f7f();
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
      }
    }
    else {
      if ((iVar4 != 0) || (DVar2 = GetLastError(), DVar2 == 0)) {
        if ((int)(iVar4 - 1U) < (int)cbMultiByte) {
          FUN_10005410(&local_44,iVar4 - 1U,'\0');
          FUN_10005490((uint *)&local_44);
          *in_stack_00000018 = 0;
          in_stack_00000018[1] = (DWORD)&PTR_vftable_10069aa8;
        }
        *(undefined4 *)this = 0;
        *(undefined4 *)((int)this + 0x10) = 0;
        *(undefined4 *)((int)this + 0x14) = 0;
        *(LPSTR ****)this = local_44;
        *(undefined4 *)((int)this + 4) = uStack_40;
        *(undefined4 *)((int)this + 8) = uStack_3c;
        *(undefined4 *)((int)this + 0xc) = uStack_38;
        *(ulonglong *)((int)this + 0x10) = CONCAT44(uStack_30,local_34);
        FUN_1001c82b();
        return;
      }
      *in_stack_00000018 = DVar2;
      in_stack_00000018[1] = (DWORD)&PTR_vftable_10069ab8;
      *(undefined4 *)this = 0;
      *(undefined4 *)((int)this + 0x10) = 0;
      *(undefined4 *)((int)this + 0x14) = 0xf;
      *(undefined1 *)this = 0;
      if (uStack_30 < 0x10) goto LAB_1001c739;
      pppppCVar3 = (LPSTR ****)local_44;
      if (0xfff < uStack_30 + 1) {
        pppppCVar3 = (LPSTR ****)local_44[-1];
        pCVar5 = (LPSTR)((int)local_44 + (-4 - (int)pppppCVar3));
        goto joined_r0x1001c790;
      }
    }
    FUN_1002e346(pppppCVar3);
LAB_1001c739:
    FUN_1001c82b();
    return;
  }
  *in_stack_00000018 = DVar2;
  in_stack_00000018[1] = (DWORD)&PTR_vftable_10069ab8;
LAB_1001c666:
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0xf;
  *(undefined1 *)this = 0;
  FUN_1001c82b();
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@1001c7ea @ 1001c7ea