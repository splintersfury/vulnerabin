undefined4 __fastcall FUN_10012320(undefined4 *param_1)

{
  uint *puVar1;
  int iVar2;
  undefined1 uVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 uStack_c;
  
  uStack_c = param_1;
  if ((param_1[4] == 0) && (uVar4 = FUN_10012650(param_1), (char)uVar4 == '\0')) {
    param_1[0x10] = "invalid BOM; must be 0xEF 0xBB 0xBF if given";
    return 0xe;
  }
  do {
    while( true ) {
      param_1[4] = param_1[4] + 1;
      param_1[5] = param_1[5] + 1;
      if (*(char *)(param_1 + 3) == '\0') {
        uVar5 = (*(code *)**(undefined4 **)*param_1)();
        param_1[2] = uVar5;
      }
      else {
        *(undefined1 *)(param_1 + 3) = 0;
      }
      if (param_1[2] != -1) {
        puVar1 = (uint *)param_1[8];
        uVar3 = (undefined1)param_1[2];
        uStack_c = (undefined4 *)CONCAT13(uVar3,(undefined3)uStack_c);
        if (puVar1 == (uint *)param_1[9]) {
          FUN_100174f0(param_1 + 7,puVar1,(undefined1 *)((int)&uStack_c + 3));
        }
        else {
          *(undefined1 *)puVar1 = uVar3;
          param_1[8] = param_1[8] + 1;
        }
      }
      iVar2 = param_1[2];
      if (iVar2 != 10) break;
      param_1[6] = param_1[6] + 1;
      param_1[5] = 0;
    }
  } while (((iVar2 == 0x20) || (iVar2 == 9)) || (iVar2 == 0xd));
  switch(iVar2) {
  default:
    param_1[0x10] = "invalid literal";
    return 0xe;
  case 0x22:
    uVar5 = FUN_100131f0(param_1);
    return uVar5;
  case 0x2c:
    return 0xd;
  case 0x2d:
  case 0x30:
  case 0x31:
  case 0x32:
  case 0x33:
  case 0x34:
  case 0x35:
  case 0x36:
  case 0x37:
  case 0x38:
  case 0x39:
    uVar5 = FUN_100128b0(param_1);
    return uVar5;
  case 0x3a:
    return 0xc;
  case 0x5b:
    return 8;
  case 0x5d:
    return 10;
  case 0x66:
    uVar5 = FUN_10012810(param_1,0x1005e254,5,2);
    return uVar5;
  case 0x6e:
    uVar5 = FUN_10012810(param_1,0x1005ee8c,4,3);
    return uVar5;
  case 0x74:
    uVar5 = FUN_10012810(param_1,0x1005e25c,4,1);
    return uVar5;
  case 0x7b:
    return 9;
  case 0x7d:
    return 0xb;
  case -1:
  case 0:
    return 0xf;
  }
}


// FUNCTION_END

// FUNCTION_START: FUN_10012540 @ 10012540