void FUN_14000f3b0(undefined8 param_1,undefined4 *param_2,undefined8 *param_3,longlong param_4,
                  short param_5,double param_6)

{
  code *pcVar1;
  undefined1 uVar2;
  uint uVar3;
  int iVar4;
  byte ****ppppbVar5;
  uint uVar6;
  undefined2 *puVar7;
  ulonglong uVar8;
  undefined1 (*pauVar9) [16];
  ulonglong uVar10;
  ulonglong uVar11;
  undefined1 uVar12;
  undefined8 *puVar13;
  undefined1 auStackY_d8 [32];
  undefined8 local_98;
  undefined8 uStack_90;
  byte ***local_88 [2];
  ulonglong local_78;
  ulonglong local_70;
  uint local_68 [2];
  char local_60;
  undefined1 local_5f;
  undefined2 local_5e;
  undefined1 auStack_5c [4];
  ulonglong local_58;
  
  local_58 = DAT_14007a060 ^ (ulonglong)auStackY_d8;
  local_78 = 0;
  local_70 = 0xf;
  local_88[0] = (byte ***)0x0;
  uVar3 = *(uint *)(param_4 + 0x18) & 0x3000;
  puVar13 = param_3;
  if (uVar3 == 0x3000) {
    uVar11 = 0xd;
    uVar10 = 0xffffffffffffffff;
  }
  else {
    uVar10 = *(ulonglong *)(param_4 + 0x20);
    if ((longlong)uVar10 < 1) {
      if (uVar10 == 0) {
        if (uVar3 == 0) {
          uVar11 = 1;
          goto LAB_14000f49d;
        }
        iVar4 = 0;
      }
      else {
        iVar4 = 6;
      }
    }
    else {
      iVar4 = (int)uVar10;
    }
    uVar11 = (ulonglong)iVar4;
    if ((uVar3 == 0x2000) &&
       (uVar3 = SUB84(param_6,0) & _DAT_14006e1f0,
       uVar6 = (uint)((ulonglong)param_6 >> 0x20) & _UNK_14006e1f4,
       _DAT_14006e168 <= (double)CONCAT44(uVar6,uVar3) &&
       (double)CONCAT44(uVar6,uVar3) != _DAT_14006e168)) {
      FUN_1400359c8(param_6,(int *)local_68);
      uVar11 = uVar11 + (longlong)
                        ((int)(((local_68[0] ^ (int)local_68[0] >> 0x1f) -
                               ((int)local_68[0] >> 0x1f)) * 0x7597) / 100000);
    }
  }
LAB_14000f49d:
  uVar8 = uVar11 + 0x32;
  if (0xffffffffffffffcd < uVar11) {
    uVar8 = 0xffffffffffffffff;
  }
  if (local_78 < uVar8) {
    uVar11 = uVar8 - local_78;
    if (local_70 - local_78 < uVar11) {
      FUN_140013950(local_88,uVar11,puVar13,uVar11,0);
    }
    else {
      ppppbVar5 = local_88;
      if (0xf < local_70) {
        ppppbVar5 = (byte ****)local_88[0];
      }
      pauVar9 = (undefined1 (*) [16])((longlong)ppppbVar5 + local_78);
      local_78 = uVar8;
      FUN_140031e00(pauVar9,0,uVar11);
      *(undefined1 *)((longlong)pauVar9 + uVar11) = 0;
    }
  }
  else {
    ppppbVar5 = local_88;
    if (0xf < local_70) {
      ppppbVar5 = (byte ****)local_88[0];
    }
    local_78 = uVar8;
    *(byte *)((longlong)ppppbVar5 + uVar8) = 0;
  }
  uVar3 = *(uint *)(param_4 + 0x18);
  local_60 = '%';
  if ((uVar3 & 0x20) != 0) {
    local_5f = 0x2b;
  }
  puVar7 = (undefined2 *)&local_5f;
  if ((uVar3 >> 5 & 1) != 0) {
    puVar7 = &local_5e;
  }
  if ((uVar3 & 0x10) != 0) {
    *(undefined1 *)puVar7 = 0x23;
    puVar7 = (undefined2 *)((longlong)puVar7 + 1);
  }
  *puVar7 = 0x2a2e;
  uVar6 = uVar3 & 0x3000;
  if ((uVar3 & 4) == 0) {
    if (uVar6 == 0x2000) {
      uVar2 = 0x66;
      goto LAB_14000f5ab;
    }
    if (uVar6 == 0x3000) {
      uVar2 = 0x61;
      goto LAB_14000f5ab;
    }
    uVar2 = 0x67;
    uVar12 = 0x65;
  }
  else {
    if (uVar6 == 0x2000) {
      uVar2 = 0x66;
      goto LAB_14000f5ab;
    }
    if (uVar6 == 0x3000) {
      uVar2 = 0x41;
      goto LAB_14000f5ab;
    }
    uVar2 = 0x47;
    uVar12 = 0x45;
  }
  if (uVar6 == 0x1000) {
    uVar2 = uVar12;
  }
LAB_14000f5ab:
  *(undefined1 *)(puVar7 + 1) = uVar2;
  *(undefined1 *)((longlong)puVar7 + 3) = 0;
  ppppbVar5 = local_88;
  if (0xf < local_70) {
    ppppbVar5 = (byte ****)local_88[0];
  }
  iVar4 = FUN_1400151d0((char *)ppppbVar5,local_78,&local_60,uVar10 & 0xffffffff);
  ppppbVar5 = local_88;
  if (0xf < local_70) {
    ppppbVar5 = (byte ****)local_88[0];
  }
  local_98 = *param_3;
  uStack_90 = param_3[1];
  FUN_140011360(param_1,param_2,(undefined4 *)&local_98,param_4,param_5,(byte *)ppppbVar5,
                (longlong)iVar4);
  if (0xf < local_70) {
    if ((0xfff < local_70 + 1) &&
       ((byte *)0x1f < (byte *)((longlong)local_88[0] + (-8 - (longlong)local_88[0][-1])))) {
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_14002f180();
  }
  FUN_14002f160(local_58 ^ (ulonglong)auStackY_d8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000f690 @ 14000f690