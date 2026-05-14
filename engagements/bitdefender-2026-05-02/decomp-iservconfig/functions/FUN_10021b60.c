void __thiscall FUN_10021b60(void *this,undefined4 *param_1)

{
  int *piVar1;
  code *pcVar2;
  int iVar3;
  int *piVar4;
  void *pvVar5;
  int *local_284;
  int *local_280;
  undefined1 local_27c [64];
  lconv *local_23c;
  char local_238;
  char local_237;
  undefined1 local_236 [512];
  undefined1 local_36;
  void *local_34 [4];
  undefined4 local_24;
  uint local_20;
  undefined4 local_1c;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004fe63;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 0xf;
  *(undefined1 *)param_1 = 0;
  local_8 = 0;
  _memset(&local_284,0,0x26c);
  piVar4 = (int *)operator_new(0x14);
  local_284 = piVar4 + 3;
  piVar1 = piVar4 + 1;
  piVar4[0] = 0;
  piVar4[1] = 0;
  piVar4[2] = 0;
  *piVar1 = 1;
  piVar4[2] = 1;
  *piVar4 = (int)std::
                 _Ref_count_obj2<class_nlohmann::detail::output_string_adapter<char,class_std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>_>_>
                 ::vftable;
  *local_284 = (int)nlohmann::detail::
                    output_string_adapter<char,class_std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>_>
                    ::vftable;
  piVar4[4] = (int)param_1;
  LOCK();
  *piVar1 = *piVar1 + 1;
  UNLOCK();
  local_8._0_1_ = 3;
  local_8._1_3_ = 0;
  local_280 = piVar4;
  _memset(local_27c,0,0x40);
  local_23c = _localeconv();
  if (local_23c->thousands_sep == (char *)0x0) {
    local_238 = '\0';
  }
  else {
    local_238 = *local_23c->thousands_sep;
  }
  if (local_23c->decimal_point == (char *)0x0) {
    local_237 = '\0';
  }
  else {
    local_237 = *local_23c->decimal_point;
  }
  _memset(local_236,0,0x200);
  local_36 = 0x20;
  local_24 = 0;
  local_20 = 0xf;
  local_34[0] = (void *)0x0;
  FUN_10008d00(local_34,0x200,' ');
  local_1c = 0;
  local_8 = CONCAT31(local_8._1_3_,5);
  LOCK();
  iVar3 = piVar4[1] + -1;
  piVar4[1] = iVar3;
  UNLOCK();
  if (iVar3 == 0) {
    (**(code **)*piVar4)();
    LOCK();
    iVar3 = piVar4[2] + -1;
    piVar4[2] = iVar3;
    UNLOCK();
    if (iVar3 == 0) {
      (**(code **)(*piVar4 + 4))();
    }
  }
  FUN_10022200(&local_284,(undefined *)this,'\0',0,(undefined *)0x0,(undefined *)0x0);
  if (0xf < local_20) {
    pvVar5 = local_34[0];
    if (0xfff < local_20 + 1) {
      pvVar5 = *(void **)((int)local_34[0] + -4);
      if (0x1f < (uint)((int)local_34[0] + (-4 - (int)pvVar5))) {
        FUN_10032f7f();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
    }
    FUN_1002e346(pvVar5);
  }
  piVar1 = local_280;
  local_24 = 0;
  local_20 = 0xf;
  local_34[0] = (void *)((uint)local_34[0] & 0xffffff00);
  if (local_280 != (int *)0x0) {
    LOCK();
    iVar3 = local_280[1] + -1;
    local_280[1] = iVar3;
    UNLOCK();
    if (iVar3 == 0) {
      (**(code **)*local_280)();
      LOCK();
      piVar4 = piVar1 + 2;
      iVar3 = *piVar4;
      *piVar4 = *piVar4 + -1;
      UNLOCK();
      if (iVar3 == 1) {
        (**(code **)(*piVar1 + 4))();
      }
    }
  }
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10021de0 @ 10021de0