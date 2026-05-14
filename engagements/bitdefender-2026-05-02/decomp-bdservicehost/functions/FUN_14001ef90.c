void FUN_14001ef90(longlong param_1)

{
  int iVar1;
  undefined8 *puVar2;
  undefined4 uVar3;
  undefined4 extraout_EAX;
  undefined4 extraout_EAX_00;
  undefined4 extraout_EAX_01;
  ulonglong uVar4;
  char *pcVar5;
  undefined8 uVar6;
  undefined1 local_res8 [8];
  
  if ((*(longlong *)(param_1 + 0x60) == 0) &&
     (uVar4 = FUN_14001f960((undefined8 *)(param_1 + 0x48)), (char)uVar4 == '\0')) {
    pcVar5 = "invalid BOM; must be 0xEF 0xBB 0xBF if given";
  }
  else {
    do {
      while( true ) {
        *(longlong *)(param_1 + 0x60) = *(longlong *)(param_1 + 0x60) + 1;
        *(longlong *)(param_1 + 0x68) = *(longlong *)(param_1 + 0x68) + 1;
        if (*(char *)(param_1 + 0x5c) == '\0') {
          uVar3 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
          *(undefined4 *)(param_1 + 0x58) = uVar3;
        }
        else {
          *(undefined1 *)(param_1 + 0x5c) = 0;
        }
        if (*(int *)(param_1 + 0x58) != -1) {
          puVar2 = *(undefined8 **)(param_1 + 0x80);
          local_res8[0] = (undefined1)*(int *)(param_1 + 0x58);
          if (puVar2 == *(undefined8 **)(param_1 + 0x88)) {
            FUN_140024dc0((longlong *)(param_1 + 0x78),puVar2,local_res8);
          }
          else {
            *(undefined1 *)puVar2 = local_res8[0];
            *(longlong *)(param_1 + 0x80) = *(longlong *)(param_1 + 0x80) + 1;
          }
        }
        iVar1 = *(int *)(param_1 + 0x58);
        if (iVar1 != 10) break;
        *(longlong *)(param_1 + 0x70) = *(longlong *)(param_1 + 0x70) + 1;
        *(undefined8 *)(param_1 + 0x68) = 0;
      }
    } while (((iVar1 == 0x20) || (iVar1 == 9)) || (iVar1 == 0xd));
    switch(iVar1) {
    default:
      pcVar5 = "invalid literal";
      break;
    case 0x22:
      uVar6 = FUN_140020640((undefined8 *)(param_1 + 0x48));
      *(int *)(param_1 + 0x40) = (int)uVar6;
      return;
    case 0x2c:
      *(undefined4 *)(param_1 + 0x40) = 0xd;
      return;
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
      uVar3 = FUN_14001fc00((undefined8 *)(param_1 + 0x48));
      *(undefined4 *)(param_1 + 0x40) = uVar3;
      return;
    case 0x3a:
      *(undefined4 *)(param_1 + 0x40) = 0xc;
      return;
    case 0x5b:
      *(undefined4 *)(param_1 + 0x40) = 8;
      return;
    case 0x5d:
      *(undefined4 *)(param_1 + 0x40) = 10;
      return;
    case 0x66:
      FUN_14001fb20((undefined8 *)(param_1 + 0x48),0x14006a978,5,2);
      *(undefined4 *)(param_1 + 0x40) = extraout_EAX_00;
      return;
    case 0x6e:
      FUN_14001fb20((undefined8 *)(param_1 + 0x48),0x14006c910,4,3);
      *(undefined4 *)(param_1 + 0x40) = extraout_EAX_01;
      return;
    case 0x74:
      FUN_14001fb20((undefined8 *)(param_1 + 0x48),0x14006a980,4,1);
      *(undefined4 *)(param_1 + 0x40) = extraout_EAX;
      return;
    case 0x7b:
      *(undefined4 *)(param_1 + 0x40) = 9;
      return;
    case 0x7d:
      *(undefined4 *)(param_1 + 0x40) = 0xb;
      return;
    case -1:
    case 0:
      *(undefined4 *)(param_1 + 0x40) = 0xf;
      return;
    }
  }
  *(char **)(param_1 + 0xb0) = pcVar5;
  *(undefined4 *)(param_1 + 0x40) = 0xe;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001f280 @ 14001f280