void __thiscall
FUN_1001c2d0(void *this,undefined4 param_1,LPCSTR param_2,undefined4 param_3,DWORD *param_4)

{
  code *pcVar1;
  short *psVar2;
  uint uVar3;
  DWORD DVar4;
  int iVar5;
  LPWSTR ****pppppWVar6;
  short *psVar7;
  uint uVar8;
  uint uStack_68;
  LPWSTR ***local_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  uint local_34;
  uint uStack_30;
  uint local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004f80d;
  local_1c = ExceptionList;
  uStack_68 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = (undefined1 *)&uStack_68;
  ExceptionList = &local_1c;
  local_2c = uStack_68;
  uVar3 = MultiByteToWideChar(0xfde9,0,param_2,-1,(LPWSTR)0x0,0);
  if ((int)uVar3 < 0) {
    DVar4 = GetLastError();
  }
  else if ((uVar3 != 0) || (DVar4 = GetLastError(), DVar4 == 0)) {
    *param_4 = 0;
    param_4[1] = (DWORD)&PTR_vftable_10069aa8;
    if (uVar3 == 0) goto LAB_1001c375;
    local_34 = 0;
    uStack_30 = 7;
    local_44 = (LPWSTR ***)0x0;
    local_14 = 1;
    FUN_1000f950(&local_44,uVar3,0);
    pppppWVar6 = &local_44;
    if (7 < uStack_30) {
      pppppWVar6 = (LPWSTR ****)local_44;
    }
    iVar5 = MultiByteToWideChar(0xfde9,0,param_2,-1,(LPWSTR)pppppWVar6,uVar3);
    if (iVar5 < 0) {
      DVar4 = GetLastError();
      *param_4 = DVar4;
      param_4[1] = (DWORD)&PTR_vftable_10069ab8;
      *(undefined4 *)this = 0;
      *(undefined4 *)((int)this + 0x10) = 0;
      *(undefined4 *)((int)this + 0x14) = 7;
      *(undefined2 *)this = 0;
      psVar2 = (short *)0x0;
      do {
        psVar7 = psVar2;
        psVar2 = psVar7 + 1;
      } while (*psVar7 != 0);
      FUN_10001d40(this,(uint *)0x0,(int)psVar7 >> 1);
      if (uStack_30 < 8) goto LAB_1001c473;
      pppppWVar6 = (LPWSTR ****)local_44;
      if (0xfff < uStack_30 * 2 + 2) {
        pppppWVar6 = (LPWSTR ****)local_44[-1];
        uVar3 = (int)local_44 + (-4 - (int)pppppWVar6);
joined_r0x1001c4d5:
        if (0x1f < uVar3) {
          FUN_10032f7f();
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
      }
    }
    else {
      if (iVar5 != 0) {
        uVar8 = iVar5 - 1;
LAB_1001c4de:
        if ((int)uVar8 < (int)uVar3) {
          if (local_34 < uVar8) {
            FUN_1000f950(&local_44,uVar8 - local_34,0);
          }
          else {
            pppppWVar6 = &local_44;
            if (7 < uStack_30) {
              pppppWVar6 = (LPWSTR ****)local_44;
            }
            local_34 = uVar8;
            *(WCHAR *)((int)pppppWVar6 + uVar8 * 2) = L'\0';
          }
          FUN_1000ea80((uint *)&local_44);
          *param_4 = 0;
          param_4[1] = (DWORD)&PTR_vftable_10069aa8;
        }
        *(undefined4 *)this = 0;
        *(undefined4 *)((int)this + 0x10) = 0;
        *(undefined4 *)((int)this + 0x14) = 0;
        *(LPWSTR ****)this = local_44;
        *(undefined4 *)((int)this + 4) = uStack_40;
        *(undefined4 *)((int)this + 8) = uStack_3c;
        *(undefined4 *)((int)this + 0xc) = uStack_38;
        *(ulonglong *)((int)this + 0x10) = CONCAT44(uStack_30,local_34);
        FUN_1001c591();
        return;
      }
      DVar4 = GetLastError();
      uVar8 = 0;
      if (DVar4 == 0) goto LAB_1001c4de;
      *param_4 = DVar4;
      param_4[1] = (DWORD)&PTR_vftable_10069ab8;
      *(undefined4 *)this = 0;
      *(undefined4 *)((int)this + 0x10) = 0;
      *(undefined4 *)((int)this + 0x14) = 7;
      *(undefined2 *)this = 0;
      if (uStack_30 < 8) goto LAB_1001c473;
      pppppWVar6 = (LPWSTR ****)local_44;
      if (0xfff < uStack_30 * 2 + 2) {
        pppppWVar6 = (LPWSTR ****)local_44[-1];
        uVar3 = (int)local_44 + (-4 - (int)pppppWVar6);
        goto joined_r0x1001c4d5;
      }
    }
    FUN_1002e346(pppppWVar6);
LAB_1001c473:
    FUN_1001c591();
    return;
  }
  *param_4 = DVar4;
  param_4[1] = (DWORD)&PTR_vftable_10069ab8;
LAB_1001c375:
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 7;
  *(undefined2 *)this = 0;
  FUN_1001c591();
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@1001c54e @ 1001c54e