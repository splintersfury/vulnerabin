void FUN_140001390(void)

{
  longlong *plVar1;
  longlong local_68 [2];
  longlong local_58 [2];
  undefined8 local_48;
  undefined8 uStack_40;
  undefined4 local_38;
  longlong local_30 [2];
  undefined8 local_20;
  undefined8 local_18;
  undefined4 local_10;
  
  local_48 = _DAT_14006e190;
  uStack_40 = _UNK_14006e198;
  local_58[0] = 0;
  FUN_1400106a0(local_58,(undefined8 *)"ACDC_POWER_SOURCE",0x11);
  local_38 = 0;
  local_20 = 0;
  local_18 = 0xf;
  local_30[0] = 0;
  FUN_1400106a0(local_30,(undefined8 *)"BATTERY_PERCENTAGE",0x12);
  local_10 = 1;
  _DAT_14007d5c0 = 0;
  DAT_14007d5c8 = (void *)0x0;
  _DAT_14007d5d0 = 0;
  DAT_14007d5c8 = operator_new(0x38);
  *(void **)DAT_14007d5c8 = DAT_14007d5c8;
  *(void **)((longlong)DAT_14007d5c8 + 8) = DAT_14007d5c8;
  DAT_14007d5d8 = 0;
  _DAT_14007d5e0 = 0;
  uRam000000014007d5e8 = 0;
  _DAT_14007d5f0 = 7;
  _DAT_14007d5f8 = 8;
  _DAT_14007d5c0 = DAT_14006e158;
  FUN_140016fb0(&DAT_14007d5d8,0x10,DAT_14007d5c8);
  plVar1 = local_58;
  do {
    FUN_140026490((float *)&DAT_14007d5c0,local_68,plVar1);
    plVar1 = plVar1 + 5;
  } while (plVar1 != (longlong *)&stack0xfffffffffffffff8);
  _eh_vector_destructor_iterator_(local_58,0x28,2,FUN_14000e8f0);
  atexit(FUN_14005a4c0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400014e0 @ 1400014e0