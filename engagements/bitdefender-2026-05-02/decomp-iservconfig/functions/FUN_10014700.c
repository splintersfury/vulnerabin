int * __thiscall FUN_10014700(void *this,undefined4 *param_1)

{
  int *piVar1;
  int iVar2;
  undefined4 *puVar3;
  int *piVar4;
  uint uVar5;
  undefined8 *puVar6;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004ee8d;
  local_10 = ExceptionList;
  uVar5 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  iVar2 = param_1[4];
  puVar3 = param_1;
  if (0xf < (uint)param_1[5]) {
    puVar3 = (undefined4 *)*param_1;
    param_1 = (undefined4 *)*param_1;
  }
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 4) = 0;
  local_8 = 0;
  if ((undefined4 *)(iVar2 + (int)puVar3) == param_1) {
    puVar6 = (undefined8 *)operator_new(0x18);
    *puVar6 = 0;
    *(undefined4 *)(puVar6 + 1) = 0;
    *(undefined4 *)((int)puVar6 + 4) = 1;
    *(undefined4 *)(puVar6 + 1) = 1;
    *(undefined ***)puVar6 =
         std::_Ref_count_obj2<class_nlohmann::detail::input_buffer_adapter>::vftable;
    *(undefined4 *)((int)puVar6 + 0xc) = nlohmann::detail::input_buffer_adapter::vftable;
    *(undefined4 *)(puVar6 + 2) = 0;
    *(undefined4 *)((int)puVar6 + 0x14) = 0;
    piVar4 = *(int **)((int)this + 4);
    *(undefined4 **)this = (undefined4 *)((int)puVar6 + 0xc);
    *(undefined8 **)((int)this + 4) = puVar6;
    if (piVar4 != (int *)0x0) {
      LOCK();
      iVar2 = piVar4[1] + -1;
      piVar4[1] = iVar2;
      UNLOCK();
      if (iVar2 == 0) {
        (**(code **)*piVar4)(uVar5);
        LOCK();
        piVar1 = piVar4 + 2;
        iVar2 = *piVar1;
        *piVar1 = *piVar1 + -1;
        UNLOCK();
        if (iVar2 == 1) {
          (**(code **)(*piVar4 + 4))();
        }
      }
    }
  }
  else {
    puVar6 = (undefined8 *)operator_new(0x18);
    *puVar6 = 0;
    *(undefined4 *)(puVar6 + 1) = 0;
    *(undefined4 *)((int)puVar6 + 4) = 1;
    *(undefined4 *)(puVar6 + 1) = 1;
    *(undefined ***)puVar6 =
         std::_Ref_count_obj2<class_nlohmann::detail::input_buffer_adapter>::vftable;
    *(undefined4 *)((int)puVar6 + 0xc) = nlohmann::detail::input_buffer_adapter::vftable;
    *(undefined4 **)(puVar6 + 2) = param_1;
    *(undefined4 **)((int)puVar6 + 0x14) = (undefined4 *)(iVar2 + (int)puVar3);
    piVar4 = *(int **)((int)this + 4);
    *(undefined4 **)this = (undefined4 *)((int)puVar6 + 0xc);
    *(undefined8 **)((int)this + 4) = puVar6;
    if (piVar4 != (int *)0x0) {
      LOCK();
      iVar2 = piVar4[1] + -1;
      piVar4[1] = iVar2;
      UNLOCK();
      if (iVar2 == 0) {
        (**(code **)*piVar4)();
        LOCK();
        piVar1 = piVar4 + 2;
        iVar2 = *piVar1;
        *piVar1 = *piVar1 + -1;
        UNLOCK();
        if (iVar2 == 1) {
          (**(code **)(*piVar4 + 4))();
        }
      }
    }
  }
  ExceptionList = local_10;
  return (int *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10014860 @ 10014860