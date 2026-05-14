char * __fastcall FUN_100236d0(char *param_1,int param_2,int param_3,undefined1 param_4)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  char *pcVar4;
  int *piVar5;
  void *this;
  undefined4 extraout_ECX;
  int *in_stack_00000030;
  undefined1 auStack_10c [28];
  undefined4 uStack_f0;
  undefined1 local_d4 [36];
  int *local_b0;
  undefined1 local_a4 [112];
  char *local_34;
  undefined1 local_30;
  undefined3 uStack_2f;
  int *local_2c;
  int *local_28;
  int *local_24;
  int *local_20;
  char *local_1c;
  undefined4 local_18;
  char *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10050081;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  _local_30 = CONCAT31(uStack_2f,param_4);
  local_18 = 0;
  local_8 = 2;
  *param_1 = '\0';
  local_34 = param_1;
  local_20 = (int *)param_2;
  local_1c = param_1;
  local_14 = param_1;
  FUN_1000f600(param_1 + 8,'\0');
  local_18 = 1;
  local_2c = (int *)0x0;
  local_28 = (int *)0x0;
  local_8 = CONCAT31(local_8._1_3_,3);
  if (param_3 == param_2) {
    piVar5 = (int *)operator_new(0x18);
    local_18 = 5;
    piVar5[0] = 0;
    piVar5[1] = 0;
    piVar5[2] = 0;
    piVar5[1] = 1;
    piVar5[2] = 1;
    *piVar5 = (int)std::_Ref_count_obj2<class_nlohmann::detail::input_buffer_adapter>::vftable;
    piVar5[4] = 0;
    piVar5[5] = 0;
  }
  else {
    piVar5 = (int *)operator_new(0x18);
    local_18 = 3;
    piVar5[0] = 0;
    piVar5[1] = 0;
    piVar5[2] = 0;
    piVar5[1] = 1;
    piVar5[2] = 1;
    *piVar5 = (int)std::_Ref_count_obj2<class_nlohmann::detail::input_buffer_adapter>::vftable;
    piVar5[4] = (int)local_20;
    piVar5[5] = param_3;
  }
  local_2c = piVar5 + 3;
  *local_2c = (int)nlohmann::detail::input_buffer_adapter::vftable;
  if (piVar5 != (int *)0x0) {
    LOCK();
    piVar5[1] = piVar5[1] + 1;
    UNLOCK();
  }
  local_14 = auStack_10c;
  local_8._0_1_ = 6;
  local_28 = piVar5;
  local_24 = local_2c;
  local_20 = piVar5;
  pcVar4 = auStack_10c;
  if (in_stack_00000030 != (int *)0x0) {
    (**(code **)*in_stack_00000030)(auStack_10c);
    pcVar4 = local_14;
  }
  local_14 = pcVar4;
  local_8._0_1_ = 5;
  this = (void *)FUN_100110c0(local_d4,&local_24,(char)_local_30);
  local_8 = CONCAT31(local_8._1_3_,7);
  uStack_f0 = 0x10023834;
  FUN_100109e0(this,extraout_ECX,param_1);
  FUN_1000fca0((int)local_a4);
  if (local_b0 != (int *)0x0) {
    (**(code **)(*local_b0 + 0x10))();
    local_b0 = (int *)0x0;
  }
  piVar2 = local_20;
  if (local_20 != (int *)0x0) {
    LOCK();
    iVar3 = local_20[1] + -1;
    local_20[1] = iVar3;
    UNLOCK();
    if (iVar3 == 0) {
      (**(code **)*local_20)();
      LOCK();
      piVar1 = piVar2 + 2;
      iVar3 = *piVar1 + -1;
      *piVar1 = iVar3;
      UNLOCK();
      if (iVar3 == 0) {
        (**(code **)(*piVar2 + 4))();
      }
    }
  }
  if (piVar5 != (int *)0x0) {
    LOCK();
    iVar3 = piVar5[1] + -1;
    piVar5[1] = iVar3;
    UNLOCK();
    if (iVar3 == 0) {
      (**(code **)*piVar5)();
      LOCK();
      piVar2 = piVar5 + 2;
      iVar3 = *piVar2;
      *piVar2 = *piVar2 + -1;
      UNLOCK();
      if (iVar3 == 1) {
        (**(code **)(*piVar5 + 4))();
      }
    }
  }
  if (in_stack_00000030 != (int *)0x0) {
    (**(code **)(*in_stack_00000030 + 0x10))();
  }
  ExceptionList = local_10;
  return local_1c;
}


// FUNCTION_END

// FUNCTION_START: FUN_100238e0 @ 100238e0