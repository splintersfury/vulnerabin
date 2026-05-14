void FUN_14000fa20(undefined8 param_1,undefined4 *param_2,undefined8 *param_3,longlong param_4,
                  short param_5,uint param_6)

{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  byte bVar4;
  undefined1 auStackY_c8 [32];
  undefined8 local_88;
  undefined8 uStack_80;
  char local_78;
  byte local_77 [15];
  char local_68 [64];
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStackY_c8;
  local_78 = '%';
  uVar1 = *(uint *)(param_4 + 0x18);
  if ((uVar1 & 0x20) != 0) {
    local_77[0] = 0x2b;
  }
  pbVar3 = local_77;
  if ((uVar1 >> 5 & 1) != 0) {
    pbVar3 = local_77 + 1;
  }
  if ((uVar1 & 8) != 0) {
    *pbVar3 = 0x23;
    pbVar3 = pbVar3 + 1;
  }
  *pbVar3 = 0x6c;
  if ((uVar1 & 0xe00) == 0x400) {
    bVar4 = 0x6f;
  }
  else if ((uVar1 & 0xe00) == 0x800) {
    bVar4 = ~((char)uVar1 << 3) & 0x20U | 0x58;
  }
  else {
    bVar4 = 100;
  }
  pbVar3[1] = bVar4;
  pbVar3[2] = 0;
  iVar2 = FUN_1400151d0(local_68,0x40,&local_78,(ulonglong)param_6);
  local_88 = *param_3;
  uStack_80 = param_3[1];
  FUN_140010c50(param_1,param_2,(undefined4 *)&local_88,param_4,param_5,local_68,(longlong)iVar2);
  FUN_14002f160(local_28 ^ (ulonglong)auStackY_c8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000fb50 @ 14000fb50