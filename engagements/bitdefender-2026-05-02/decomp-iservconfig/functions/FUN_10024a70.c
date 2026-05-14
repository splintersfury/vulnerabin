void __thiscall FUN_10024a70(void *this,void *param_1)

{
  code *pcVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  uint *puVar5;
  char cVar6;
  LPCWSTR pWVar7;
  BOOL BVar8;
  void *pvVar9;
  LPCWSTR pWVar10;
  SIZE_T uBytes;
  uint *puVar11;
  uint uStack_70;
  char local_58 [8];
  DATA_BLOB local_50;
  DATA_BLOB local_48;
  DATA_BLOB local_40;
  undefined8 local_38;
  int local_30;
  uint local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  puStack_18 = &LAB_100501ad;
  local_1c = ExceptionList;
  uStack_70 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = (undefined1 *)&uStack_70;
  ExceptionList = &local_1c;
  local_38 = 0;
  local_30 = 0;
  pWVar7 = (LPCWSTR)((int)this + 0x1c);
  local_14 = 0;
  if (7 < *(uint *)((int)this + 0x30)) {
    pWVar7 = *(LPCWSTR *)pWVar7;
  }
  pWVar10 = (LPCWSTR)((int)this + 4);
  if (7 < *(uint *)((int)this + 0x18)) {
    pWVar10 = *(LPCWSTR *)pWVar10;
  }
                    /* WARNING: Load size is inaccurate */
  local_2c = uStack_70;
  cVar6 = FUN_100270b0(*this,pWVar10,pWVar7,(int *)&local_38);
  if (cVar6 == '\0') {
    if ((uint *)local_38 == (uint *)0x0) goto LAB_10024d66;
    pvVar9 = (uint *)local_38;
    if (((uint)(local_30 - (int)(uint *)local_38) < 0x1000) ||
       (pvVar9 = *(void **)((int)(uint *)local_38 + -4),
       (uint)((int)(uint *)local_38 + (-4 - (int)pvVar9)) < 0x20)) {
      FUN_1002e346(pvVar9);
      FUN_10024d64();
      return;
    }
  }
  else {
    local_40.cbData = 0;
    local_40.pbData = (BYTE *)0x0;
    local_14 = CONCAT31(local_14._1_3_,1);
    uBytes = local_38._4_4_ - (int)(uint *)local_38;
    local_50.cbData = uBytes;
    local_50.pbData = (BYTE *)LocalAlloc(0,uBytes);
    puVar5 = (uint *)local_38;
    FUN_100301d0((uint *)local_50.pbData,(uint *)local_38,uBytes);
    local_48.cbData = 0x25;
    local_48.pbData = (BYTE *)LocalAlloc(0,0x25);
    uVar4 = _UNK_1005e8b8;
    uVar3 = _UNK_1005e8b4;
    uVar2 = _UNK_1005e8b0;
    *(undefined4 *)local_48.pbData = _DAT_1005e8ac;
    *(undefined4 *)(local_48.pbData + 4) = uVar2;
    *(undefined4 *)(local_48.pbData + 8) = uVar3;
    *(undefined4 *)(local_48.pbData + 0xc) = uVar4;
    uVar4 = _UNK_1005e8c8;
    uVar3 = _UNK_1005e8c4;
    uVar2 = _UNK_1005e8c0;
    *(undefined4 *)(local_48.pbData + 0x10) = _DAT_1005e8bc;
    *(undefined4 *)(local_48.pbData + 0x14) = uVar2;
    *(undefined4 *)(local_48.pbData + 0x18) = uVar3;
    *(undefined4 *)(local_48.pbData + 0x1c) = uVar4;
    *(undefined4 *)(local_48.pbData + 0x20) = DAT_1005e8cc;
    local_48.pbData[0x24] = DAT_1005e8d0;
    BVar8 = CryptUnprotectData(&local_50,(LPWSTR *)0x0,&local_48,(PVOID)0x0,
                               (CRYPTPROTECT_PROMPTSTRUCT *)0x0,4,&local_40);
    if (local_48.pbData != (BYTE *)0x0) {
      LocalFree(local_48.pbData);
    }
    if ((uint *)local_50.pbData != (uint *)0x0) {
      LocalFree(local_50.pbData);
    }
    puVar11 = puVar5;
    if (BVar8 == 1) {
      if (local_40.cbData != 0) {
        local_14._0_1_ = 2;
        FUN_100236d0(local_58,(int)local_40.pbData,(int)(local_40.pbData + local_40.cbData),1);
        local_14 = CONCAT31(local_14._1_3_,3);
        cVar6 = FUN_10025ae0(local_58,param_1);
        if (cVar6 != '\0') {
          FUN_1000e760(local_58);
          if (local_40.pbData != (BYTE *)0x0) {
            LocalFree(local_40.pbData);
          }
          if (puVar5 != (uint *)0x0) {
            if ((0xfff < (uint)(local_30 - (int)puVar5)) &&
               (puVar11 = (uint *)puVar5[-1], 0x1f < (uint)((int)puVar5 + (-4 - (int)puVar11))))
            goto LAB_10024d8b;
            FUN_1002e346(puVar11);
          }
LAB_10024d66:
          ExceptionList = local_1c;
          FUN_1002e315(local_2c ^ (uint)&stack0xfffffff0);
          return;
        }
        FUN_1000e760(local_58);
        if (local_40.pbData != (BYTE *)0x0) {
          LocalFree(local_40.pbData);
        }
        if (puVar5 == (uint *)0x0) goto LAB_10024d66;
        if (((uint)(local_30 - (int)puVar5) < 0x1000) ||
           (puVar11 = (uint *)puVar5[-1], (uint)((int)puVar5 + (-4 - (int)puVar11)) < 0x20))
        goto LAB_10024cf6;
        goto LAB_10024d8b;
      }
      if (local_40.pbData != (BYTE *)0x0) {
        LocalFree(local_40.pbData);
      }
      if (puVar5 == (uint *)0x0) goto LAB_10024d66;
      if (((uint)(local_30 - (int)puVar5) < 0x1000) ||
         (puVar11 = (uint *)puVar5[-1], (uint)((int)puVar5 + (-4 - (int)puVar11)) < 0x20))
      goto LAB_10024cf6;
    }
    else {
      if (local_40.pbData != (BYTE *)0x0) {
        LocalFree(local_40.pbData);
      }
      if (puVar5 == (uint *)0x0) goto LAB_10024d66;
      if ((uint)(local_30 - (int)puVar5) < 0x1000) {
LAB_10024cf6:
        FUN_1002e346(puVar11);
        FUN_10024d64();
        return;
      }
      if ((uint)((int)puVar5 + (-4 - (int)puVar5[-1])) < 0x20) {
        FUN_1002e346((void *)puVar5[-1]);
        FUN_10024d64();
        return;
      }
    }
  }
  FUN_10032f7f();
LAB_10024d8b:
  FUN_10032f7f();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch@10024d42 @ 10024d42