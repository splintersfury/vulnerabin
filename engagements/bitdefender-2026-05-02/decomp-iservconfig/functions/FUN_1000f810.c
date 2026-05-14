char * __fastcall FUN_1000f810(char *param_1,undefined4 *param_2,undefined1 param_3)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  char *pcVar4;
  void *this;
  undefined4 extraout_ECX;
  int *in_stack_0000002c;
  undefined1 auStack_108 [28];
  undefined4 uStack_ec;
  undefined1 local_d0 [36];
  int *local_ac;
  undefined1 local_a0 [116];
  char *local_2c;
  undefined4 local_28;
  int *local_24;
  undefined1 local_20;
  undefined3 uStack_1f;
  undefined4 local_1c;
  char *local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004ea61;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  _local_20 = CONCAT31(uStack_1f,param_3);
  local_1c = 0;
  local_8 = 2;
  *param_1 = '\0';
  local_2c = param_1;
  local_18 = param_1;
  FUN_1000f600(param_1 + 8,'\0');
  local_24 = (int *)param_2[1];
  local_1c = 1;
  if (local_24 != (int *)0x0) {
    LOCK();
    local_24[1] = local_24[1] + 1;
    UNLOCK();
    local_24 = (int *)param_2[1];
  }
  local_28 = *param_2;
  local_18 = auStack_108;
  local_8._0_1_ = 4;
  pcVar4 = auStack_108;
  if (in_stack_0000002c != (int *)0x0) {
    (**(code **)*in_stack_0000002c)(auStack_108);
    pcVar4 = local_18;
  }
  local_18 = pcVar4;
  local_8._0_1_ = 3;
  this = (void *)FUN_100110c0(local_d0,&local_28,(char)_local_20);
  local_8 = CONCAT31(local_8._1_3_,5);
  uStack_ec = 0x1000f8c8;
  FUN_100109e0(this,extraout_ECX,param_1);
  FUN_1000fca0((int)local_a0);
  if (local_ac != (int *)0x0) {
    (**(code **)(*local_ac + 0x10))();
    local_ac = (int *)0x0;
  }
  piVar3 = local_24;
  if (local_24 != (int *)0x0) {
    LOCK();
    iVar2 = local_24[1] + -1;
    local_24[1] = iVar2;
    UNLOCK();
    if (iVar2 == 0) {
      (**(code **)*local_24)();
      LOCK();
      piVar1 = piVar3 + 2;
      iVar2 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar2 == 1) {
        (**(code **)(*piVar3 + 4))();
      }
    }
  }
  if (in_stack_0000002c != (int *)0x0) {
    (**(code **)(*in_stack_0000002c + 0x10))();
  }
  ExceptionList = local_10;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000f950 @ 1000f950