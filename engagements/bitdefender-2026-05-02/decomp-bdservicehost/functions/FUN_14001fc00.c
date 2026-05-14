void FUN_14001fc00(undefined8 *param_1)

{
  undefined8 *puVar1;
  undefined1 *puVar2;
  int iVar3;
  undefined4 uVar4;
  char *pcVar5;
  char *pcVar6;
  ulong *puVar7;
  ulonglong uVar8;
  longlong lVar9;
  char cVar10;
  uint uVar11;
  ulonglong uVar12;
  int iVar13;
  ulonglong *puVar14;
  undefined1 *puVar15;
  ulonglong uVar16;
  undefined8 uVar17;
  undefined1 auStack_68 [32];
  undefined1 local_48 [8];
  char *local_40;
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStack_68;
  pcVar5 = (char *)(param_1 + 9);
  pcVar6 = pcVar5;
  if (0xf < (ulonglong)param_1[0xc]) {
    pcVar6 = *(char **)pcVar5;
  }
  param_1[0xb] = 0;
  *pcVar6 = '\0';
  puVar1 = (undefined8 *)param_1[6];
  param_1[7] = puVar1;
  local_48[0] = *(undefined1 *)(param_1 + 2);
  if (puVar1 == (undefined8 *)param_1[8]) {
    FUN_140024dc0(param_1 + 6,puVar1,local_48);
  }
  else {
    *(undefined1 *)puVar1 = local_48[0];
    param_1[7] = param_1[7] + 1;
  }
  iVar13 = 5;
  uVar11 = *(uint *)(param_1 + 2);
  uVar8 = (ulonglong)uVar11;
  cVar10 = (char)uVar11;
  switch(uVar11) {
  case 0x2d:
    uVar12 = param_1[0xb];
    uVar16 = param_1[0xc];
    if (uVar12 < uVar16) {
      param_1[0xb] = uVar12 + 1;
      pcVar6 = pcVar5;
      if (0xf < uVar16) {
        pcVar6 = *(char **)pcVar5;
      }
      pcVar6[uVar12] = cVar10;
      pcVar6[uVar12 + 1] = '\0';
    }
    else {
      FUN_1400137e0((undefined8 *)pcVar5,uVar8,uVar16,cVar10);
    }
    break;
  case 0x30:
    goto switchD_14001fc9a_caseD_30;
  case 0x31:
  case 0x32:
  case 0x33:
  case 0x34:
  case 0x35:
  case 0x36:
  case 0x37:
  case 0x38:
  case 0x39:
    puVar2 = (undefined1 *)param_1[0xb];
    puVar15 = (undefined1 *)param_1[0xc];
    if (puVar2 < puVar15) {
      param_1[0xb] = puVar2 + 1;
      pcVar6 = pcVar5;
      if ((undefined1 *)0xf < puVar15) {
        pcVar6 = *(char **)pcVar5;
      }
      pcVar6[(longlong)puVar2] = cVar10;
      (pcVar6 + 1)[(longlong)puVar2] = '\0';
    }
    else {
      FUN_1400137e0((undefined8 *)pcVar5,uVar8,puVar15,cVar10);
    }
    goto LAB_14001ff20;
  }
  iVar13 = 6;
  param_1[3] = param_1[3] + 1;
  param_1[4] = param_1[4] + 1;
  if (*(char *)((longlong)param_1 + 0x14) == '\0') {
    uVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
    *(undefined4 *)(param_1 + 2) = uVar4;
  }
  else {
    *(undefined1 *)((longlong)param_1 + 0x14) = 0;
  }
  if (*(int *)(param_1 + 2) != -1) {
    local_48[0] = (undefined1)*(int *)(param_1 + 2);
    puVar1 = (undefined8 *)param_1[7];
    if (puVar1 == (undefined8 *)param_1[8]) {
      FUN_140024dc0(param_1 + 6,puVar1,local_48);
    }
    else {
      *(undefined1 *)puVar1 = local_48[0];
      param_1[7] = param_1[7] + 1;
    }
  }
  uVar11 = *(uint *)(param_1 + 2);
  uVar8 = (ulonglong)uVar11;
  if (uVar11 == 10) {
    param_1[5] = param_1[5] + 1;
    param_1[4] = 0;
switchD_14001fdd1_caseD_a:
    pcVar5 = "invalid number; expected digit after \'-\'";
  }
  else {
    switch(uVar11) {
    case 0x30:
switchD_14001fc9a_caseD_30:
      puVar15 = (undefined1 *)param_1[0xc];
      puVar2 = (undefined1 *)param_1[0xb];
      if (puVar2 < puVar15) {
        param_1[0xb] = puVar2 + 1;
        pcVar6 = pcVar5;
        if ((undefined1 *)0xf < puVar15) {
          pcVar6 = *(char **)pcVar5;
        }
        (pcVar6 + 1)[(longlong)puVar2] = '\0';
        pcVar6[(longlong)puVar2] = (char)uVar8;
      }
      else {
        FUN_1400137e0((undefined8 *)pcVar5,uVar8,puVar15,(char)uVar8);
      }
      param_1[3] = param_1[3] + 1;
      param_1[4] = param_1[4] + 1;
      if (*(char *)((longlong)param_1 + 0x14) == '\0') {
        uVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
        *(undefined4 *)(param_1 + 2) = uVar4;
      }
      else {
        *(undefined1 *)((longlong)param_1 + 0x14) = 0;
      }
      if (*(int *)(param_1 + 2) != -1) {
        local_48[0] = (undefined1)*(int *)(param_1 + 2);
        puVar1 = (undefined8 *)param_1[7];
        if (puVar1 == (undefined8 *)param_1[8]) {
          puVar15 = local_48;
          FUN_140024dc0(param_1 + 6,puVar1,puVar15);
        }
        else {
          *(undefined1 *)puVar1 = local_48[0];
          param_1[7] = param_1[7] + 1;
        }
      }
      uVar11 = *(uint *)(param_1 + 2);
      uVar12 = (ulonglong)uVar11;
      iVar3 = iVar13;
      if (uVar11 == 10) {
LAB_1400203b8:
        iVar13 = iVar3;
        param_1[4] = 0;
        param_1[5] = param_1[5] + 1;
switchD_14001ffa4_caseD_2f:
        *(undefined1 *)((longlong)param_1 + 0x14) = 1;
        param_1[3] = param_1[3] + -1;
        if (param_1[4] == 0) {
          if (param_1[5] != 0) {
            param_1[5] = param_1[5] + -1;
          }
        }
        else {
          param_1[4] = param_1[4] + -1;
        }
        if (uVar11 != 0xffffffff) {
          param_1[7] = param_1[7] + -1;
        }
        local_40 = (char *)0x0;
        puVar7 = __doserrno();
        *puVar7 = 0;
        if (iVar13 == 5) {
          pcVar6 = pcVar5;
          if (0xf < (ulonglong)param_1[0xc]) {
            pcVar6 = *(char **)pcVar5;
          }
          uVar8 = FID_conflict_strtoull(pcVar6,&local_40,10);
          puVar7 = __doserrno();
          if (*puVar7 == 0) {
            param_1[0xf] = uVar8;
            goto LAB_14001fd91;
          }
        }
        else if (iVar13 == 6) {
          pcVar6 = pcVar5;
          if (0xf < (ulonglong)param_1[0xc]) {
            pcVar6 = *(char **)pcVar5;
          }
          lVar9 = FID_conflict__strtoi64(pcVar6,&local_40,10);
          puVar7 = __doserrno();
          if (*puVar7 == 0) {
            param_1[0xe] = lVar9;
            goto LAB_14001fd91;
          }
        }
        if (0xf < (ulonglong)param_1[0xc]) {
          pcVar5 = *(char **)pcVar5;
        }
        uVar17 = FUN_14003e064((longlong)pcVar5,(longlong *)&local_40);
        param_1[0x10] = uVar17;
        goto LAB_14001fd91;
      }
      if (uVar11 == 0x2e) {
        uVar8 = param_1[0xc];
        goto LAB_14001ffdb;
      }
      if ((uVar11 != 0x45) && (uVar11 != 0x65)) goto switchD_14001ffa4_caseD_2f;
switchD_140020140_caseD_45:
      puVar2 = (undefined1 *)param_1[0xb];
      puVar15 = (undefined1 *)param_1[0xc];
      cVar10 = (char)uVar12;
      if (puVar2 < puVar15) {
        param_1[0xb] = puVar2 + 1;
        pcVar6 = pcVar5;
        if ((undefined1 *)0xf < puVar15) {
          pcVar6 = *(char **)pcVar5;
        }
        pcVar6[(longlong)puVar2] = cVar10;
        (pcVar6 + 1)[(longlong)puVar2] = '\0';
      }
      else {
LAB_14001feaa:
        FUN_1400137e0((undefined8 *)pcVar5,uVar12,puVar15,cVar10);
      }
LAB_14001feb2:
      iVar13 = 7;
      param_1[3] = param_1[3] + 1;
      param_1[4] = param_1[4] + 1;
      if (*(char *)((longlong)param_1 + 0x14) == '\0') {
        uVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
        *(undefined4 *)(param_1 + 2) = uVar4;
      }
      else {
        *(undefined1 *)((longlong)param_1 + 0x14) = 0;
      }
      if (*(int *)(param_1 + 2) != -1) {
        local_48[0] = (undefined1)*(int *)(param_1 + 2);
        puVar1 = (undefined8 *)param_1[7];
        if (puVar1 == (undefined8 *)param_1[8]) {
          FUN_140024dc0(param_1 + 6,puVar1,local_48);
        }
        else {
          *(undefined1 *)puVar1 = local_48[0];
          param_1[7] = param_1[7] + 1;
        }
      }
      uVar11 = *(uint *)(param_1 + 2);
      uVar8 = (ulonglong)uVar11;
      if (uVar11 == 10) {
        param_1[5] = param_1[5] + 1;
        param_1[4] = 0;
switchD_140020215_caseD_2c:
        pcVar5 = "invalid number; expected \'+\', \'-\', or digit after exponent";
      }
      else {
        switch(uVar11) {
        case 0x2b:
        case 0x2d:
          uVar12 = param_1[0xb];
          uVar16 = param_1[0xc];
          if (uVar12 < uVar16) {
            param_1[0xb] = uVar12 + 1;
            pcVar6 = pcVar5;
            if (0xf < uVar16) {
              pcVar6 = *(char **)pcVar5;
            }
            pcVar6[uVar12] = (char)uVar11;
            pcVar6[uVar12 + 1] = '\0';
          }
          else {
            FUN_1400137e0((undefined8 *)pcVar5,uVar8,uVar16,(char)uVar11);
          }
          param_1[3] = param_1[3] + 1;
          param_1[4] = param_1[4] + 1;
          if (*(char *)((longlong)param_1 + 0x14) == '\0') {
            uVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
            *(undefined4 *)(param_1 + 2) = uVar4;
          }
          else {
            *(undefined1 *)((longlong)param_1 + 0x14) = 0;
          }
          if (*(int *)(param_1 + 2) != -1) {
            local_48[0] = (undefined1)*(int *)(param_1 + 2);
            puVar1 = (undefined8 *)param_1[7];
            if (puVar1 == (undefined8 *)param_1[8]) {
              FUN_140024dc0(param_1 + 6,puVar1,local_48);
            }
            else {
              *(undefined1 *)puVar1 = local_48[0];
              param_1[7] = param_1[7] + 1;
            }
          }
          uVar11 = *(uint *)(param_1 + 2);
          uVar8 = (ulonglong)uVar11;
          if (uVar11 == 10) {
            param_1[5] = param_1[5] + 1;
            param_1[4] = 0;
          }
          else {
            switch(uVar11) {
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
              goto switchD_140020215_caseD_30;
            }
          }
          pcVar5 = "invalid number; expected digit after exponent sign";
          break;
        default:
          goto switchD_140020215_caseD_2c;
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
switchD_140020215_caseD_30:
          puVar15 = (undefined1 *)param_1[0xc];
          puVar2 = (undefined1 *)param_1[0xb];
          cVar10 = (char)uVar8;
          if (puVar15 <= puVar2) goto LAB_140020302;
          param_1[0xb] = puVar2 + 1;
          pcVar6 = pcVar5;
          if ((undefined1 *)0xf < puVar15) {
            pcVar6 = *(char **)pcVar5;
          }
          (pcVar6 + 1)[(longlong)puVar2] = '\0';
          pcVar6[(longlong)puVar2] = cVar10;
LAB_140020310:
          param_1[3] = param_1[3] + 1;
          param_1[4] = param_1[4] + 1;
          if (*(char *)((longlong)param_1 + 0x14) == '\0') {
            uVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
            *(undefined4 *)(param_1 + 2) = uVar4;
          }
          else {
            *(undefined1 *)((longlong)param_1 + 0x14) = 0;
          }
          if (*(int *)(param_1 + 2) != -1) {
            local_48[0] = (undefined1)*(int *)(param_1 + 2);
            puVar1 = (undefined8 *)param_1[7];
            if (puVar1 == (undefined8 *)param_1[8]) {
              puVar15 = local_48;
              FUN_140024dc0(param_1 + 6,puVar1,puVar15);
            }
            else {
              *(undefined1 *)puVar1 = local_48[0];
              param_1[7] = param_1[7] + 1;
            }
          }
          uVar11 = *(uint *)(param_1 + 2);
          cVar10 = (char)uVar11;
          iVar3 = 7;
          if (uVar11 == 10) goto LAB_1400203b8;
          switch(uVar11) {
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
            uVar12 = param_1[0xb];
            uVar8 = param_1[0xc];
            if (uVar12 < uVar8) {
              param_1[0xb] = uVar12 + 1;
              pcVar6 = pcVar5;
              if (0xf < uVar8) {
                pcVar6 = *(char **)pcVar5;
              }
              pcVar6[uVar12] = cVar10;
              pcVar6[uVar12 + 1] = '\0';
            }
            else {
LAB_140020302:
              FUN_1400137e0((undefined8 *)pcVar5,uVar8,puVar15,cVar10);
            }
            goto LAB_140020310;
          }
          goto switchD_14001ffa4_caseD_2f;
        }
      }
      break;
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x36:
    case 0x37:
    case 0x38:
    case 0x39:
      puVar2 = (undefined1 *)param_1[0xb];
      puVar15 = (undefined1 *)param_1[0xc];
      cVar10 = (char)uVar11;
      if (puVar15 <= puVar2) goto LAB_14001ff0d;
      param_1[0xb] = puVar2 + 1;
      pcVar6 = pcVar5;
      if ((undefined1 *)0xf < puVar15) {
        pcVar6 = *(char **)pcVar5;
      }
      pcVar6[(longlong)puVar2] = cVar10;
      (pcVar6 + 1)[(longlong)puVar2] = '\0';
LAB_14001ff20:
      puVar14 = param_1 + 0xc;
      param_1[3] = param_1[3] + 1;
      param_1[4] = param_1[4] + 1;
      if (*(char *)((longlong)param_1 + 0x14) == '\0') {
        uVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
        *(undefined4 *)(param_1 + 2) = uVar4;
      }
      else {
        *(undefined1 *)((longlong)param_1 + 0x14) = 0;
      }
      if (*(int *)(param_1 + 2) != -1) {
        local_48[0] = (undefined1)*(int *)(param_1 + 2);
        puVar1 = (undefined8 *)param_1[7];
        if (puVar1 == (undefined8 *)param_1[8]) {
          puVar15 = local_48;
          FUN_140024dc0(param_1 + 6,puVar1,puVar15);
        }
        else {
          *(undefined1 *)puVar1 = local_48[0];
          param_1[7] = param_1[7] + 1;
        }
      }
      uVar11 = *(uint *)(param_1 + 2);
      cVar10 = (char)uVar11;
      iVar3 = iVar13;
      if (uVar11 == 10) goto LAB_1400203b8;
      switch(uVar11) {
      case 0x2e:
        uVar8 = *puVar14;
        break;
      default:
        goto switchD_14001ffa4_caseD_2f;
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
        uVar12 = param_1[0xb];
        uVar8 = *puVar14;
        if (uVar12 < uVar8) {
          param_1[0xb] = uVar12 + 1;
          pcVar6 = pcVar5;
          if (0xf < uVar8) {
            pcVar6 = *(char **)pcVar5;
          }
          pcVar6[uVar12] = cVar10;
          pcVar6[uVar12 + 1] = '\0';
        }
        else {
LAB_14001ff0d:
          FUN_1400137e0((undefined8 *)pcVar5,uVar8,puVar15,cVar10);
        }
        goto LAB_14001ff20;
      case 0x45:
      case 0x65:
        uVar8 = param_1[0xb];
        uVar12 = *puVar14;
        if (uVar12 <= uVar8) goto LAB_14001feaa;
        param_1[0xb] = uVar8 + 1;
        pcVar6 = pcVar5;
        if (0xf < uVar12) {
          pcVar6 = *(char **)pcVar5;
        }
        pcVar6[uVar8] = cVar10;
        pcVar6[uVar8 + 1] = '\0';
        goto LAB_14001feb2;
      }
LAB_14001ffdb:
      uVar12 = param_1[0xb];
      cVar10 = *(char *)(param_1 + 0x11);
      if (uVar12 < uVar8) {
        param_1[0xb] = uVar12 + 1;
        pcVar6 = pcVar5;
        if (0xf < uVar8) {
          pcVar6 = *(char **)pcVar5;
        }
        pcVar6[uVar12 + 1] = '\0';
        pcVar6[uVar12] = cVar10;
      }
      else {
        FUN_1400137e0((undefined8 *)pcVar5,uVar8,puVar15,cVar10);
      }
      iVar13 = 7;
      param_1[3] = param_1[3] + 1;
      param_1[4] = param_1[4] + 1;
      if (*(char *)((longlong)param_1 + 0x14) == '\0') {
        uVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
        *(undefined4 *)(param_1 + 2) = uVar4;
      }
      else {
        *(undefined1 *)((longlong)param_1 + 0x14) = 0;
      }
      if (*(int *)(param_1 + 2) != -1) {
        local_48[0] = (undefined1)*(int *)(param_1 + 2);
        puVar1 = (undefined8 *)param_1[7];
        if (puVar1 == (undefined8 *)param_1[8]) {
          FUN_140024dc0(param_1 + 6,puVar1,local_48);
        }
        else {
          *(undefined1 *)puVar1 = local_48[0];
          param_1[7] = param_1[7] + 1;
        }
      }
      uVar11 = *(uint *)(param_1 + 2);
      uVar12 = (ulonglong)uVar11;
      if (uVar11 == 10) {
        param_1[5] = param_1[5] + 1;
        param_1[4] = 0;
      }
      else {
        switch(uVar11) {
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
          uVar8 = param_1[0xb];
          uVar16 = param_1[0xc];
          if (uVar8 < uVar16) goto LAB_140020153;
LAB_1400200ae:
          FUN_1400137e0((undefined8 *)pcVar5,uVar12,uVar16,(char)uVar12);
LAB_1400200c0:
          param_1[3] = param_1[3] + 1;
          param_1[4] = param_1[4] + 1;
          if (*(char *)((longlong)param_1 + 0x14) == '\0') {
            uVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
            *(undefined4 *)(param_1 + 2) = uVar4;
          }
          else {
            *(undefined1 *)((longlong)param_1 + 0x14) = 0;
          }
          if (*(int *)(param_1 + 2) != -1) {
            local_48[0] = (undefined1)*(int *)(param_1 + 2);
            puVar1 = (undefined8 *)param_1[7];
            if (puVar1 == (undefined8 *)param_1[8]) {
              FUN_140024dc0(param_1 + 6,puVar1,local_48);
            }
            else {
              *(undefined1 *)puVar1 = local_48[0];
              param_1[7] = param_1[7] + 1;
            }
          }
          uVar11 = *(uint *)(param_1 + 2);
          uVar12 = (ulonglong)uVar11;
          iVar3 = 7;
          if (uVar11 != 10) {
            switch(uVar11) {
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
              goto switchD_140020140_caseD_30;
            default:
              goto switchD_14001ffa4_caseD_2f;
            case 0x45:
            case 0x65:
              goto switchD_140020140_caseD_45;
            }
          }
          goto LAB_1400203b8;
        }
      }
      pcVar5 = "invalid number; expected digit after \'.\'";
      break;
    default:
      goto switchD_14001fdd1_caseD_a;
    }
  }
  param_1[0xd] = pcVar5;
LAB_14001fd91:
  FUN_14002f160(local_38 ^ (ulonglong)auStack_68);
  return;
switchD_140020140_caseD_30:
  uVar8 = param_1[0xb];
  uVar16 = param_1[0xc];
  if (uVar16 <= uVar8) goto LAB_1400200ae;
LAB_140020153:
  param_1[0xb] = uVar8 + 1;
  pcVar6 = pcVar5;
  if (0xf < uVar16) {
    pcVar6 = *(char **)pcVar5;
  }
  pcVar6[uVar8] = (char)uVar12;
  pcVar6[uVar8 + 1] = '\0';
  goto LAB_1400200c0;
}


// FUNCTION_END

// FUNCTION_START: FUN_140020640 @ 140020640