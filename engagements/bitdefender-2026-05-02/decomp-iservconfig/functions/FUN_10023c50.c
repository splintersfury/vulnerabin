int FUN_10023c50(uint param_1,uint param_2)

{
  longlong lVar1;
  uint uVar2;
  uint uVar3;
  int local_c;
  uint local_8;
  
  local_c = 1;
  local_8 = param_2;
  if (param_2 != 0) goto LAB_10023ca4;
  if (param_1 < 10) {
    return 1;
  }
  do {
    if (local_8 == 0) {
      if (param_1 < 100) {
        return local_c + 1;
      }
      if (param_1 < 1000) {
        return local_c + 2;
      }
      if (param_1 < 10000) {
        return local_c + 3;
      }
    }
LAB_10023ca4:
    do {
      lVar1 = (ulonglong)local_8 * 0x3886594b + ((ulonglong)param_1 * 0x3886594b >> 0x20);
      uVar2 = (uint)((ulonglong)lVar1 >> 0x20);
      uVar3 = (int)((ulonglong)param_1 * 0x346dc5d6 >> 0x20) +
              (uint)CARRY4((uint)((ulonglong)param_1 * 0x346dc5d6),(uint)lVar1);
      lVar1 = (ulonglong)local_8 * 0x346dc5d6 +
              (ulonglong)CONCAT14(CARRY4(uVar2,uVar3),uVar2 + uVar3);
      local_8 = (uint)((ulonglong)lVar1 >> 0x20);
      param_1 = (uint)lVar1 >> 0xb | local_8 * 0x200000;
      local_c = local_c + 4;
      local_8 = local_8 >> 0xb;
    } while (local_8 != 0);
    if (param_1 < 10) {
      return local_c;
    }
  } while( true );
}


// FUNCTION_END

// FUNCTION_START: FUN_10023d50 @ 10023d50