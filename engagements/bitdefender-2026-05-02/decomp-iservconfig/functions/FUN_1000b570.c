uint * __fastcall FUN_1000b570(uint *param_1,uint *param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  
  iVar2 = (int)param_2 - (int)param_1 >> 1;
  if (1 < iVar2) {
    uVar1 = *param_1;
    uVar3 = uVar1 >> 0x10;
    if ((uVar1 & 0xffffffdf) - 0x3a0041 < 0x1a) {
      return param_1 + 1;
    }
    if (((uVar1 & 0xffff) == 0x5c) || ((uVar1 & 0xffff) == 0x2f)) {
      if (iVar2 < 4) {
        if (iVar2 < 3) {
          return param_1;
        }
      }
      else if ((((*(short *)((int)param_1 + 6) == 0x5c) || (*(short *)((int)param_1 + 6) == 0x2f))
               && ((iVar2 == 4 || (((short)param_1[2] != 0x5c && ((short)param_1[2] != 0x2f)))))) &&
              ((((uVar3 == 0x5c || (uVar3 == 0x2f)) &&
                (((short)param_1[1] == 0x3f || ((short)param_1[1] == 0x2e)))) ||
               (((short)(uVar1 >> 0x10) == 0x3f && ((short)param_1[1] == 0x3f)))))) {
        return (uint *)((int)param_1 + 6);
      }
      if ((((uVar3 == 0x5c) || (uVar3 == 0x2f)) && ((short)param_1[1] != 0x5c)) &&
         (((short)param_1[1] != 0x2f && (param_1 = (uint *)((int)param_1 + 6), param_1 != param_2)))
         ) {
        while (((short)*param_1 != 0x5c && ((short)*param_1 != 0x2f))) {
          param_1 = (uint *)((int)param_1 + 2);
          if (param_1 == param_2) {
            return param_1;
          }
        }
      }
    }
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000b650 @ 1000b650