void __fastcall FUN_1000b9c0(uint *param_1,LPCWSTR param_2,int *param_3)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined1 auStack_34 [4];
  undefined4 local_30 [4];
  uint local_20;
  int local_1c;
  uint local_c;
  
  local_c = DAT_10069054 ^ (uint)auStack_34;
  if (7 < *(uint *)(param_2 + 10)) {
    param_2 = *(LPCWSTR *)param_2;
  }
  iVar1 = FUN_1002d8bb(param_2,local_30,3,0xffffffff);
  if (iVar1 != 0) {
    uVar3 = 0xffff;
    switch(iVar1) {
    case 2:
    case 3:
    case 0x35:
    case 0x7b:
      uVar2 = 1;
      break;
    default:
      uVar2 = 0;
    }
    goto LAB_1000ba66;
  }
  uVar3 = 0x1ff;
  if ((local_20 & 1) != 0) {
    uVar3 = 0x16d;
  }
  if ((local_20 >> 10 & 1) != 0) {
    if (local_1c == -0x5ffffff4) {
      uVar2 = 4;
      goto LAB_1000ba66;
    }
    if (local_1c == -0x5ffffffd) {
      uVar2 = 10;
      goto LAB_1000ba66;
    }
  }
  uVar2 = local_20 >> 4 & 1 | 2;
LAB_1000ba66:
  *param_3 = iVar1;
  param_3[1] = (int)&PTR_vftable_10069aa8;
  *param_1 = uVar2;
  param_1[1] = uVar3;
  FUN_1002e315(local_c ^ (uint)auStack_34);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000bb10 @ 1000bb10