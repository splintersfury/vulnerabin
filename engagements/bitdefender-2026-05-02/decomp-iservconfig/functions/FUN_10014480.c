undefined4 * __thiscall FUN_10014480(void *this,undefined4 *param_1)

{
  code *pcVar1;
  void *pvVar2;
  undefined4 *puVar3;
  uint local_7c [6];
  uint local_64 [6];
  undefined4 *local_4c;
  void *local_48 [4];
  undefined4 local_38;
  uint local_34;
  void *local_30 [4];
  undefined4 local_20;
  uint local_1c;
  undefined4 local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004ee56;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_4c = param_1;
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 0xf;
  *(undefined1 *)param_1 = 0;
  param_1[6] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0xf;
  *(undefined1 *)(param_1 + 6) = 0;
  local_8 = 0;
  local_18 = 1;
  local_38 = 0;
  local_34 = 0xf;
  local_48[0] = (void *)0x0;
  FUN_10008e70(local_48,(uint *)"version",7);
  local_8 = 1;
  pvVar2 = (void *)FUN_1000e620(this,(uint *)local_48);
  FUN_100142f0(pvVar2,local_7c);
  local_8._0_1_ = 2;
  local_20 = 0;
  local_1c = 0xf;
  local_30[0] = (void *)0x0;
  FUN_10008e70(local_30,(uint *)&DAT_1005ea18,4);
  local_8 = CONCAT31(local_8._1_3_,3);
  pvVar2 = (void *)FUN_1000e620(this,(uint *)local_30);
  FUN_100142f0(pvVar2,local_64);
  FUN_1000ec10(param_1,(int *)local_7c);
  FUN_1000ec10(param_1 + 6,(int *)local_64);
  FUN_1000bb10((int *)local_7c);
  if (0xf < local_1c) {
    pvVar2 = local_30[0];
    if (0xfff < local_1c + 1) {
      pvVar2 = *(void **)((int)local_30[0] + -4);
      if (0x1f < (uint)((int)local_30[0] + (-4 - (int)pvVar2))) goto LAB_10014615;
    }
    FUN_1002e346(pvVar2);
  }
  if (0xf < local_34) {
    pvVar2 = local_48[0];
    if (0xfff < local_34 + 1) {
      pvVar2 = *(void **)((int)local_48[0] + -4);
      if (0x1f < (uint)((int)local_48[0] + (-4 - (int)pvVar2))) {
LAB_10014615:
        FUN_10032f7f();
        pcVar1 = (code *)swi(3);
        puVar3 = (undefined4 *)(*pcVar1)();
        return puVar3;
      }
    }
    FUN_1002e346(pvVar2);
  }
  ExceptionList = local_10;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10014620 @ 10014620