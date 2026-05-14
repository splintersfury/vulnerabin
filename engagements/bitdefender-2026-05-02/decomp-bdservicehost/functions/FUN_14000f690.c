void FUN_14000f690(undefined8 param_1,undefined4 *param_2,undefined8 *param_3,longlong param_4,
                  short param_5,undefined8 param_6)

{
  uint uVar1;
  int iVar2;
  undefined2 *puVar3;
  byte bVar4;
  undefined1 auStackY_c8 [32];
  undefined8 local_88;
  undefined8 uStack_80;
  char local_78;
  undefined1 local_77;
  undefined2 local_76;
  byte abStack_74 [12];
  char local_68 [64];
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStackY_c8;
  local_78 = '%';
  uVar1 = *(uint *)(param_4 + 0x18);
  if ((uVar1 & 0x20) != 0) {
    local_77 = 0x2b;
  }
  puVar3 = (undefined2 *)&local_77;
  if ((uVar1 >> 5 & 1) != 0) {
    puVar3 = &local_76;
  }
  if ((uVar1 & 8) != 0) {
    *(undefined1 *)puVar3 = 0x23;
    puVar3 = (undefined2 *)((longlong)puVar3 + 1);
  }
  *puVar3 = 0x3649;
  *(undefined1 *)(puVar3 + 1) = 0x34;
  if ((uVar1 & 0xe00) == 0x400) {
    bVar4 = 0x6f;
  }
  else if ((uVar1 & 0xe00) == 0x800) {
    bVar4 = ~((char)uVar1 << 3) & 0x20U | 0x58;
  }
  else {
    bVar4 = 0x75;
  }
  *(byte *)((longlong)puVar3 + 3) = bVar4;
  *(undefined1 *)(puVar3 + 2) = 0;
  iVar2 = FUN_1400151d0(local_68,0x40,&local_78,param_6);
  local_88 = *param_3;
  uStack_80 = param_3[1];
  FUN_140010c50(param_1,param_2,(undefined4 *)&local_88,param_4,param_5,local_68,(longlong)iVar2);
  FUN_14002f160(local_28 ^ (ulonglong)auStackY_c8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000f7c0 @ 14000f7c0