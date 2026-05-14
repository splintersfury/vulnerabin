void __thiscall
FUN_100068b0(void *this,undefined4 *param_1,undefined4 param_2,int *param_3,int param_4,
            undefined4 param_5)

{
  uint uVar1;
  undefined1 auStack_54 [4];
  char local_50 [68];
  uint local_c;
  
  local_c = DAT_10069054 ^ (uint)auStack_54;
  uVar1 = FUN_10008b60(local_50,0x40,"%p");
  FUN_100074c0(this,param_1,param_2,param_3,param_4,param_5,local_50,uVar1);
  FUN_1002e315(local_c ^ (uint)auStack_54);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10006920 @ 10006920

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */