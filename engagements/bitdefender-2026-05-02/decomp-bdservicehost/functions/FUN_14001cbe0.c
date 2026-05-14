longlong * FUN_14001cbe0(longlong *param_1,char ****param_2,undefined8 param_3,undefined8 param_4)

{
  int *piVar1;
  int iVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  char ****ppppcVar5;
  char ***local_158 [7];
  char ****local_120;
  undefined4 local_118;
  undefined8 *local_110;
  undefined8 *local_108;
  undefined4 local_100;
  undefined1 local_fc;
  undefined8 local_f8;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 uStack_d0;
  undefined8 local_c8;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined *local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined1 local_88;
  undefined1 local_80;
  undefined1 *local_78;
  undefined8 *local_70;
  undefined8 *local_68;
  undefined1 local_60 [56];
  undefined1 *local_28;
  
  local_28 = (undefined1 *)0x0;
  local_78 = local_60;
  ppppcVar5 = param_2;
  puVar3 = (undefined8 *)operator_new(0x28);
  *puVar3 = 0;
  puVar3[1] = 0;
  *(undefined4 *)(puVar3 + 1) = 1;
  *(undefined4 *)((longlong)puVar3 + 0xc) = 1;
  *puVar3 = std::_Ref_count_obj2<class_nlohmann::detail::input_stream_adapter>::vftable;
  local_110 = puVar3 + 2;
  *local_110 = nlohmann::detail::input_stream_adapter::vftable;
  puVar3[3] = param_1;
  puVar3[4] = *(undefined8 *)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
  LOCK();
  *(int *)(puVar3 + 1) = *(int *)(puVar3 + 1) + 1;
  UNLOCK();
  local_120 = (char ****)0x0;
  local_70 = local_110;
  local_68 = puVar3;
  if (local_28 != (undefined1 *)0x0) {
    ppppcVar5 = local_158;
    local_120 = (char ****)(*(code *)PTR__guard_dispatch_icall_14005b538)();
  }
  local_118 = 0;
  local_100 = 0xffffffff;
  local_fc = 0;
  local_f8 = 0;
  local_f0 = 0;
  local_e8 = 0;
  local_e0 = 0;
  local_d8 = 0;
  uStack_d0 = 0;
  local_b8 = 0;
  local_b0 = 0xf;
  local_c8 = 0;
  local_a8 = &DAT_14006a933;
  local_a0 = 0;
  local_98 = 0;
  local_90 = 0;
  local_108 = puVar3;
  puVar4 = (undefined8 *)FUN_140035e08();
  local_88 = 0x2e;
  if ((undefined1 *)*puVar4 != (undefined1 *)0x0) {
    local_88 = *(undefined1 *)*puVar4;
  }
  local_80 = 1;
  FUN_14001ef90((longlong)local_158);
  if (local_28 != (undefined1 *)0x0) {
    ppppcVar5 = (char ****)CONCAT71((int7)((ulonglong)local_60 >> 8),local_28 != local_60);
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
    local_28 = (undefined1 *)0x0;
  }
  FUN_14001db80((longlong)local_158,ppppcVar5,param_2,param_4);
  FUN_14001d5f0((longlong)&local_110);
  if (local_120 != (char ****)0x0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)
              (local_120,CONCAT71((int7)((ulonglong)local_158 >> 8),local_120 != local_158));
    local_120 = (char ****)0x0;
  }
  LOCK();
  piVar1 = (int *)(puVar3 + 1);
  iVar2 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  if (iVar2 == 1) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(puVar3);
    LOCK();
    piVar1 = (int *)((longlong)puVar3 + 0xc);
    iVar2 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (iVar2 == 1) {
      (*(code *)PTR__guard_dispatch_icall_14005b538)(puVar3);
    }
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001cdf0 @ 14001cdf0