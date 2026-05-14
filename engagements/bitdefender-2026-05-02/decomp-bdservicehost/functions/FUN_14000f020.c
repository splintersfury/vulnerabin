void FUN_14000f020(undefined8 param_1,undefined4 *param_2,undefined8 *param_3,longlong param_4,
                  short param_5,undefined8 param_6)

{
  int iVar1;
  undefined1 auStackY_b8 [32];
  undefined8 local_78;
  undefined8 uStack_70;
  char local_68 [64];
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStackY_b8;
  iVar1 = FUN_1400151d0(local_68,0x40,"%p",param_6);
  local_78 = *param_3;
  uStack_70 = param_3[1];
  FUN_140010c50(param_1,param_2,(undefined4 *)&local_78,param_4,param_5,local_68,(longlong)iVar1);
  FUN_14002f160(local_28 ^ (ulonglong)auStackY_b8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000f0d0 @ 14000f0d0

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */