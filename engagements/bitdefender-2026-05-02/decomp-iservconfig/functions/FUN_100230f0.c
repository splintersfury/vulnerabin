void __thiscall FUN_100230f0(void *this,undefined4 *param_1)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  uint *puVar5;
  uint uVar6;
  int iVar7;
  uint local_c0 [6];
  uint local_a8 [6];
  uint local_90 [6];
  int local_78 [7];
  uint local_5c;
  undefined4 *local_58;
  int local_54;
  uint local_50;
  int local_4c;
  byte local_46;
  byte local_45;
  uint local_44 [6];
  uint local_2c [6];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004ff89;
  local_10 = ExceptionList;
  uVar1 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_58 = param_1;
  iVar7 = 0;
  local_45 = 0;
  local_54 = 0;
  local_4c = 0;
  local_50 = 0;
  uVar6 = local_5c;
  local_14 = uVar1;
  if (param_1[4] == 0) goto LAB_10023345;
  do {
    puVar3 = local_58;
    if (0xf < (uint)local_58[5]) {
      puVar3 = (undefined4 *)*local_58;
    }
    local_5c = (uint)*(byte *)((int)puVar3 + local_50);
    local_46 = (&DAT_10060520)[local_5c];
    if (local_45 == 0) {
      uVar6 = 0xffU >> (local_46 & 0x1f) & local_5c;
    }
    else {
      uVar6 = uVar6 << 6 | local_5c & 0x3f;
    }
    local_45 = (&DAT_10060620)[(uint)local_45 * 0x10 + (uint)local_46];
    if (local_45 == 0) {
      switch(uVar6) {
      case 8:
        *(undefined2 *)((int)this + iVar7 + 0x4e) = 0x625c;
        iVar4 = 2;
        break;
      case 9:
        *(undefined2 *)((int)this + iVar7 + 0x4e) = 0x745c;
        iVar4 = 2;
        break;
      case 10:
        *(undefined2 *)((int)this + iVar7 + 0x4e) = 0x6e5c;
        iVar4 = 2;
        break;
      default:
        if (uVar6 < 0x20) {
          FUN_1001bf40((int)this + iVar7 + 0x4e,7,"\\u%04x");
          iVar4 = 6;
        }
        else {
          puVar3 = local_58;
          if (0xf < (uint)local_58[5]) {
            puVar3 = (undefined4 *)*local_58;
          }
          *(undefined1 *)((int)this + iVar7 + 0x4e) = *(undefined1 *)((int)puVar3 + local_50);
          iVar4 = 1;
        }
        break;
      case 0xc:
        *(undefined2 *)((int)this + iVar7 + 0x4e) = 0x665c;
        iVar4 = 2;
        break;
      case 0xd:
        *(undefined2 *)((int)this + iVar7 + 0x4e) = 0x725c;
        iVar4 = 2;
        break;
      case 0x22:
        *(undefined2 *)((int)this + iVar7 + 0x4e) = 0x225c;
        iVar4 = 2;
        break;
      case 0x5c:
        *(undefined2 *)((int)this + iVar7 + 0x4e) = 0x5c5c;
        iVar4 = 2;
      }
      iVar7 = iVar7 + iVar4;
      if (0x200U - iVar7 < 0xd) {
                    /* WARNING: Load size is inaccurate */
        (**(code **)(**this + 4))((int)this + 0x4e,iVar7,uVar1);
        iVar7 = 0;
      }
      local_4c = 0;
      local_54 = iVar7;
    }
    else if (local_45 == 1) {
      iVar4 = *(int *)((int)this + 0x268);
      if (iVar4 == 0) {
        FUN_10008e40(local_44,3,'\0');
        local_8 = 0;
        uVar6 = FUN_10005c90((int)local_44);
        iVar7 = FUN_10008ce0(local_44,0);
        FUN_1001bf40(iVar7,uVar6,"%.2X");
        puVar5 = (uint *)FUN_1001bf60((char *)local_2c,local_50);
        local_8._0_1_ = 1;
        puVar5 = FUN_10005f20(local_a8,(uint *)"invalid UTF-8 byte at index ",puVar5);
        local_8._0_1_ = 2;
        puVar5 = FUN_10014250(local_c0,puVar5,(uint *)&DAT_10060388);
        local_8._0_1_ = 3;
        puVar5 = FUN_100142a0(local_90,puVar5,local_44);
        local_8 = CONCAT31(local_8._1_3_,4);
        goto LAB_10023491;
      }
      if ((iVar4 == 1) || (iVar4 == 2)) {
        uVar2 = local_50 - 1;
        if (local_4c == 0) {
          uVar2 = local_50;
        }
        local_50 = uVar2;
        iVar7 = local_54;
        if (*(int *)((int)this + 0x268) == 1) {
          *(undefined1 *)((int)this + local_54 + 0x4e) = 0xef;
          *(undefined2 *)((int)this + local_54 + 0x4f) = 0xbdbf;
          iVar7 = local_54 + 3;
          if (0x200U - iVar7 < 0xd) {
                    /* WARNING: Load size is inaccurate */
            (**(code **)(**this + 4))((int)this + 0x4e,iVar7);
            iVar7 = 0;
          }
        }
        local_54 = iVar7;
        local_4c = 0;
        local_45 = 0;
        iVar7 = local_54;
      }
    }
    else {
      puVar3 = local_58;
      if (0xf < (uint)local_58[5]) {
        puVar3 = (undefined4 *)*local_58;
      }
      *(undefined1 *)((int)this + iVar7 + 0x4e) = *(undefined1 *)((int)puVar3 + local_50);
      iVar7 = iVar7 + 1;
      local_4c = local_4c + 1;
    }
    local_50 = local_50 + 1;
  } while (local_50 < (uint)local_58[4]);
  if (local_45 == 0) {
    if (iVar7 == 0) goto LAB_10023345;
                    /* WARNING: Load size is inaccurate */
    iVar4 = **this;
  }
  else {
    iVar7 = *(int *)((int)this + 0x268);
    if (iVar7 == 0) {
      FUN_10008e40(local_2c,3,'\0');
      local_8 = 5;
      FUN_10023530(local_58);
      uVar6 = FUN_10005c90((int)local_2c);
      iVar7 = FUN_10008ce0(local_2c,0);
      FUN_1001bf40(iVar7,uVar6,"%.2X");
      puVar5 = FUN_10014120(local_90,(uint *)"incomplete UTF-8 string; last byte: 0x",local_2c);
      local_8 = CONCAT31(local_8._1_3_,6);
LAB_10023491:
      FUN_1000ad90(local_78,0x13c,puVar5);
                    /* WARNING: Subroutine does not return */
      __CxxThrowException_8(local_78,&DAT_10067608);
    }
    if (iVar7 == 1) {
                    /* WARNING: Load size is inaccurate */
      (**(code **)(**this + 4))((int)this + 0x4e,local_54);
                    /* WARNING: Load size is inaccurate */
      (**(code **)(**this + 4))(&DAT_100603d8,3);
      goto LAB_10023345;
    }
    if (iVar7 != 2) goto LAB_10023345;
                    /* WARNING: Load size is inaccurate */
    iVar4 = **this;
    iVar7 = local_54;
  }
  (**(code **)(iVar4 + 4))((int)this + 0x4e,iVar7);
LAB_10023345:
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10023530 @ 10023530