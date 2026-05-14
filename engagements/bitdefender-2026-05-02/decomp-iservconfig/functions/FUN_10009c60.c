undefined4 __fastcall FUN_10009c60(ushort *param_1,ushort *param_2,int param_3)

{
  ushort uVar1;
  ushort uVar2;
  ushort *puVar3;
  bool bVar4;
  bool bVar5;
  
  if (param_3 == 0) {
    return 0;
  }
  uVar1 = *param_2;
  uVar2 = *param_1;
  if (uVar1 <= uVar2) {
    bVar4 = uVar2 < uVar1;
    bVar5 = uVar2 == uVar1;
    puVar3 = param_2;
    do {
      if (!bVar4 && !bVar5) {
        return 1;
      }
      if (param_3 == 1) {
        return 0;
      }
      uVar1 = *(ushort *)((int)param_1 + (2 - (int)param_2) + (int)puVar3);
      puVar3 = puVar3 + 1;
      param_3 = param_3 + -1;
      bVar4 = uVar1 < *puVar3;
      bVar5 = uVar1 == *puVar3;
    } while (!bVar4);
  }
  return 0xffffffff;
}


// FUNCTION_END

// FUNCTION_START: FUN_10009cc0 @ 10009cc0