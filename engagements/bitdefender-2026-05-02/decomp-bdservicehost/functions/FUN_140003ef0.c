void FUN_140003ef0(longlong *param_1,longlong param_2,undefined8 param_3)

{
  undefined8 *puVar1;
  uint uVar2;
  undefined1 auStack_168 [32];
  undefined8 local_148;
  longlong *local_140;
  undefined8 local_138 [2];
  longlong local_128 [2];
  longlong local_118;
  undefined1 local_110 [80];
  undefined2 auStack_c0 [76];
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_168;
  local_148 = param_3;
  local_140 = param_1;
  FUN_140031e00((undefined1 (*) [16])local_128,0,0xf8);
  FUN_14000d640(local_128);
  *(undefined2 *)((longlong)auStack_c0 + (longlong)*(int *)(local_118 + 4)) = 0x30;
  FUN_140002df0((longlong)(local_110 + (longlong)*(int *)(local_118 + 4) + -8));
  for (uVar2 = 0; uVar2 < *(uint *)(param_2 + 8); uVar2 = uVar2 + 1) {
    puVar1 = FUN_14002e378(local_138,2);
    (*(code *)PTR__guard_dispatch_icall_14005b538)
              (local_110 + (longlong)*(int *)(local_118 + 4) + -8,puVar1[1]);
    FUN_14000e200(&local_118,
                  (uint)*(byte *)((ulonglong)((*(int *)(param_2 + 8) - uVar2) - 1) +
                                 *(longlong *)(param_2 + 0x10)));
  }
  FUN_1400100a0((longlong)local_110,param_1);
  FUN_140004010(local_128);
  FUN_14002f160(local_28 ^ (ulonglong)auStack_168);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140004010 @ 140004010