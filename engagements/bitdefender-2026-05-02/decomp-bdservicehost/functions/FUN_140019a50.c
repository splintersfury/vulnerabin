undefined8 * FUN_140019a50(undefined8 *param_1,uint param_2)

{
  longlong lVar1;
  uint uVar2;
  
  *param_1 = nlohmann::detail::input_stream_adapter::vftable;
  lVar1 = (longlong)*(int *)(*(longlong *)param_1[1] + 4) + (longlong)param_1[1];
  uVar2 = 4;
  if (*(longlong *)(lVar1 + 0x48) != 0) {
    uVar2 = 0;
  }
  FUN_140002cd0(lVar1,uVar2 | *(uint *)(lVar1 + 0x10) & 1,'\0');
  if ((param_2 & 1) != 0) {
    FUN_14002f180();
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140019ac0 @ 140019ac0