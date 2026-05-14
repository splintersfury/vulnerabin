void __thiscall
FUN_10006dc0(void *this,undefined4 *param_1,undefined4 param_2,int *param_3,int param_4,
            undefined4 param_5)

{
  char *pcVar1;
  uint uVar2;
  undefined1 auStack_5c [4];
  undefined1 local_58 [8];
  char local_50 [68];
  uint local_c;
  
  local_c = DAT_10069054 ^ (uint)auStack_5c;
  pcVar1 = FUN_100078b0(this,local_58,"lu",*(uint *)(param_4 + 0x14));
  uVar2 = FUN_10008b60(local_50,0x40,pcVar1);
  FUN_100074c0(this,param_1,param_2,param_3,param_4,param_5,local_50,uVar2);
  FUN_1002e315(local_c ^ (uint)auStack_5c);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10006e40 @ 10006e40