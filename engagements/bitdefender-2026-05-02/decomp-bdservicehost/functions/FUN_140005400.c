uint * FUN_140005400(uint *param_1,uint *param_2)

{
  uint uVar1;
  longlong lVar2;
  short sVar3;
  
  lVar2 = (longlong)param_2 - (longlong)param_1 >> 1;
  if (1 < lVar2) {
    uVar1 = *param_1;
    if ((uVar1 & 0xffffffdf) - 0x3a0041 < 0x1a) {
      return param_1 + 1;
    }
    if (((short)uVar1 == 0x5c) || ((short)uVar1 == 0x2f)) {
      sVar3 = (short)(uVar1 >> 0x10);
      if (lVar2 < 4) {
        if (lVar2 < 3) {
          return param_1;
        }
      }
      else if ((((*(short *)((longlong)param_1 + 6) == 0x5c) ||
                (*(short *)((longlong)param_1 + 6) == 0x2f)) &&
               ((lVar2 == 4 || (((short)param_1[2] != 0x5c && ((short)param_1[2] != 0x2f)))))) &&
              ((((sVar3 == 0x5c || (sVar3 == 0x2f)) &&
                (((short)param_1[1] == 0x3f || ((short)param_1[1] == 0x2e)))) ||
               ((sVar3 == 0x3f && ((short)param_1[1] == 0x3f)))))) {
        return (uint *)((longlong)param_1 + 6);
      }
      if ((((sVar3 == 0x5c) || (sVar3 == 0x2f)) && ((short)param_1[1] != 0x5c)) &&
         (((short)param_1[1] != 0x2f &&
          (param_1 = (uint *)((longlong)param_1 + 6), param_1 != param_2)))) {
        while (((short)*param_1 != 0x5c && ((short)*param_1 != 0x2f))) {
          param_1 = (uint *)((longlong)param_1 + 2);
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

// FUNCTION_START: FUN_1400054f0 @ 1400054f0