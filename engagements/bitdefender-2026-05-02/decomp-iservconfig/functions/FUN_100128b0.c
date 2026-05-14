void __fastcall FUN_100128b0(undefined4 *param_1)

{
  uint *puVar1;
  uint uVar2;
  undefined4 uVar3;
  wchar_t *pwVar4;
  int *piVar5;
  char cVar6;
  uint uVar7;
  uint *puVar8;
  uint uVar9;
  wchar_t *_Str;
  ulonglong uVar10;
  longlong lVar11;
  double dVar12;
  undefined1 local_29;
  wchar_t *local_28;
  uint local_24;
  uint *local_20;
  uint local_1c;
  uint *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004ed80;
  local_10 = ExceptionList;
  uVar2 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  _Str = (wchar_t *)(param_1 + 10);
  local_8 = 0;
  local_18 = param_1 + 0xf;
  pwVar4 = _Str;
  if (0xf < (uint)param_1[0xf]) {
    pwVar4 = *(wchar_t **)_Str;
  }
  param_1[0xe] = 0;
  *(char *)pwVar4 = '\0';
  puVar8 = (uint *)param_1[7];
  param_1[8] = puVar8;
  local_29 = *(undefined1 *)(param_1 + 2);
  local_14 = uVar2;
  if (puVar8 == (uint *)param_1[9]) {
    FUN_100174f0(param_1 + 7,puVar8,&local_29);
  }
  else {
    *(undefined1 *)puVar8 = local_29;
    param_1[8] = param_1[8] + 1;
  }
  local_8 = 0xffffffff;
  uVar7 = param_1[2];
  local_24 = 5;
  cVar6 = (char)uVar7;
  switch(uVar7) {
  case 0x2d:
    uVar9 = param_1[0xe];
    local_24 = uVar7 & 0xff;
    if (uVar9 < (uint)param_1[0xf]) {
      param_1[0xe] = uVar9 + 1;
      pwVar4 = _Str;
      if (0xf < (uint)param_1[0xf]) {
        pwVar4 = *(wchar_t **)_Str;
      }
      *(char *)((int)pwVar4 + uVar9) = cVar6;
      *(char *)((int)pwVar4 + uVar9 + 1) = '\0';
    }
    else {
      local_20 = (uint *)((uint)local_20 & 0xffffff00);
      FUN_10014ac0(_Str,uVar7,local_20,cVar6);
    }
    break;
  case 0x30:
    uVar2 = param_1[0xe];
    uVar9 = param_1[0xf];
    local_20 = (uint *)CONCAT31(local_20._1_3_,cVar6);
    puVar8 = local_20;
    if (uVar9 <= uVar2) goto LAB_10012ab6;
    goto LAB_10012a9a;
  case 0x31:
  case 0x32:
  case 0x33:
  case 0x34:
  case 0x35:
  case 0x36:
  case 0x37:
  case 0x38:
  case 0x39:
    uVar2 = param_1[0xe];
    local_1c = CONCAT31(local_1c._1_3_,cVar6);
    if (uVar2 < (uint)param_1[0xf]) {
      param_1[0xe] = uVar2 + 1;
      pwVar4 = _Str;
      if (0xf < (uint)param_1[0xf]) {
        pwVar4 = *(wchar_t **)_Str;
      }
      *(char *)((int)pwVar4 + uVar2) = cVar6;
      *(char *)((int)pwVar4 + uVar2 + 1) = '\0';
      local_20 = local_18;
      puVar8 = local_18;
    }
    else {
      local_20 = (uint *)((uint)local_20._1_3_ << 8);
      FUN_10014ac0(_Str,uVar7,local_20,cVar6);
      local_20 = local_18;
      puVar8 = local_18;
    }
    goto LAB_10012ba0;
  }
  param_1[4] = param_1[4] + 1;
  param_1[5] = param_1[5] + 1;
  local_24 = 6;
  if (*(char *)(param_1 + 3) == '\0') {
    uVar3 = (*(code *)**(undefined4 **)*param_1)(uVar2);
    param_1[2] = uVar3;
  }
  else {
    *(undefined1 *)(param_1 + 3) = 0;
  }
  if (param_1[2] != -1) {
    puVar8 = (uint *)param_1[8];
    local_29 = (undefined1)param_1[2];
    if (puVar8 == (uint *)param_1[9]) {
      FUN_100174f0(param_1 + 7,puVar8,&local_29);
    }
    else {
      *(undefined1 *)puVar8 = local_29;
      param_1[8] = param_1[8] + 1;
    }
  }
  uVar7 = param_1[2];
  if (uVar7 == 10) {
    param_1[6] = param_1[6] + 1;
    param_1[5] = 0;
  }
  else {
    cVar6 = (char)uVar7;
    switch(uVar7) {
    case 0x30:
      uVar2 = param_1[0xe];
      uVar9 = param_1[0xf];
      local_18 = (uint *)CONCAT31(local_18._1_3_,cVar6);
      puVar8 = local_18;
      if (uVar2 < uVar9) {
LAB_10012a9a:
        param_1[0xe] = uVar2 + 1;
        pwVar4 = _Str;
        if (0xf < uVar9) {
          pwVar4 = *(wchar_t **)_Str;
        }
        *(char *)((int)pwVar4 + uVar2) = (char)uVar7;
        *(char *)((int)pwVar4 + uVar2 + 1) = '\0';
      }
      else {
LAB_10012ab6:
        local_1c = local_1c & 0xffffff00;
        FUN_10014ac0(_Str,uVar7,local_1c,(char)puVar8);
      }
      param_1[4] = param_1[4] + 1;
      param_1[5] = param_1[5] + 1;
      if (*(char *)(param_1 + 3) == '\0') {
        uVar3 = (*(code *)**(undefined4 **)*param_1)();
        param_1[2] = uVar3;
      }
      else {
        *(undefined1 *)(param_1 + 3) = 0;
      }
      if (param_1[2] != -1) {
        puVar8 = (uint *)param_1[8];
        local_29 = (undefined1)param_1[2];
        if (puVar8 == (uint *)param_1[9]) {
          FUN_100174f0(param_1 + 7,puVar8,&local_29);
        }
        else {
          *(undefined1 *)puVar8 = local_29;
          param_1[8] = param_1[8] + 1;
        }
      }
      uVar2 = param_1[2];
      if (uVar2 == 10) {
LAB_10012fef:
        param_1[6] = param_1[6] + 1;
        param_1[5] = 0;
      }
      else {
        if (uVar2 == 0x2e) {
          uVar2 = param_1[0xf];
          goto LAB_10012c54;
        }
        if ((uVar2 == 0x45) || (uVar2 == 0x65)) {
switchD_10012d91_caseD_45:
          uVar7 = param_1[0xe];
          local_18 = (uint *)CONCAT31(local_18._1_3_,(char)uVar2);
          if (uVar7 < (uint)param_1[0xf]) {
            param_1[0xe] = uVar7 + 1;
            pwVar4 = _Str;
            if (0xf < (uint)param_1[0xf]) {
              pwVar4 = *(wchar_t **)_Str;
            }
            *(char *)((int)pwVar4 + uVar7) = (char)uVar2;
            *(char *)((int)pwVar4 + uVar7 + 1) = '\0';
          }
          else {
LAB_10012dea:
            local_1c = local_1c & 0xffffff00;
            FUN_10014ac0(_Str,uVar2,local_1c,(char)local_18);
          }
LAB_10012dfc:
          param_1[4] = param_1[4] + 1;
          param_1[5] = param_1[5] + 1;
          local_24 = 7;
          if (*(char *)(param_1 + 3) == '\0') {
            uVar3 = (*(code *)**(undefined4 **)*param_1)();
            param_1[2] = uVar3;
          }
          else {
            *(undefined1 *)(param_1 + 3) = 0;
          }
          if (param_1[2] != -1) {
            puVar8 = (uint *)param_1[8];
            local_29 = (undefined1)param_1[2];
            if (puVar8 == (uint *)param_1[9]) {
              FUN_100174f0(param_1 + 7,puVar8,&local_29);
            }
            else {
              *(undefined1 *)puVar8 = local_29;
              param_1[8] = param_1[8] + 1;
            }
          }
          uVar7 = param_1[2];
          if (uVar7 == 10) {
            param_1[6] = param_1[6] + 1;
            param_1[5] = 0;
          }
          else {
            switch(uVar7) {
            case 0x2b:
            case 0x2d:
              uVar2 = param_1[0xe];
              cVar6 = (char)uVar7;
              local_18 = (uint *)CONCAT31(local_18._1_3_,cVar6);
              if (uVar2 < (uint)param_1[0xf]) {
                param_1[0xe] = uVar2 + 1;
                pwVar4 = _Str;
                if (0xf < (uint)param_1[0xf]) {
                  pwVar4 = *(wchar_t **)_Str;
                }
                *(char *)((int)pwVar4 + uVar2) = cVar6;
                *(char *)((int)pwVar4 + uVar2 + 1) = '\0';
              }
              else {
                local_1c = local_1c & 0xffffff00;
                FUN_10014ac0(_Str,uVar7,local_1c,cVar6);
              }
              param_1[4] = param_1[4] + 1;
              param_1[5] = param_1[5] + 1;
              if (*(char *)(param_1 + 3) == '\0') {
                uVar3 = (*(code *)**(undefined4 **)*param_1)();
                param_1[2] = uVar3;
              }
              else {
                *(undefined1 *)(param_1 + 3) = 0;
              }
              if (param_1[2] != -1) {
                puVar8 = (uint *)param_1[8];
                local_29 = (undefined1)param_1[2];
                if (puVar8 == (uint *)param_1[9]) {
                  FUN_100174f0(param_1 + 7,puVar8,&local_29);
                }
                else {
                  *(undefined1 *)puVar8 = local_29;
                  param_1[8] = param_1[8] + 1;
                }
              }
              uVar7 = param_1[2];
              if (uVar7 == 10) {
                param_1[6] = param_1[6] + 1;
                param_1[5] = 0;
              }
              else {
                switch(uVar7) {
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
                  goto switchD_10012e72_caseD_30;
                }
              }
              param_1[0x10] = "invalid number; expected digit after exponent sign";
              goto LAB_10012a5b;
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
switchD_10012e72_caseD_30:
              uVar2 = param_1[0xe];
              local_18 = (uint *)CONCAT31(local_18._1_3_,(char)uVar7);
              if ((uint)param_1[0xf] <= uVar2) goto LAB_10012f4d;
              param_1[0xe] = uVar2 + 1;
              pwVar4 = _Str;
              if (0xf < (uint)param_1[0xf]) {
                pwVar4 = *(wchar_t **)_Str;
              }
              *(char *)((int)pwVar4 + uVar2 + 1) = '\0';
              *(char *)((int)pwVar4 + uVar2) = (char)uVar7;
LAB_10012f60:
              param_1[4] = param_1[4] + 1;
              param_1[5] = param_1[5] + 1;
              if (*(char *)(param_1 + 3) == '\0') {
                uVar3 = (*(code *)**(undefined4 **)*param_1)();
                param_1[2] = uVar3;
              }
              else {
                *(undefined1 *)(param_1 + 3) = 0;
              }
              if (param_1[2] != -1) {
                puVar8 = (uint *)param_1[8];
                local_29 = (undefined1)param_1[2];
                if (puVar8 == (uint *)param_1[9]) {
                  FUN_100174f0(param_1 + 7,puVar8,&local_29);
                }
                else {
                  *(undefined1 *)puVar8 = local_29;
                  param_1[8] = param_1[8] + 1;
                }
              }
              uVar2 = param_1[2];
              if (uVar2 == 10) goto LAB_10012fef;
              switch(uVar2) {
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
                uVar7 = param_1[0xe];
                local_18 = (uint *)CONCAT31(local_18._1_3_,(char)uVar2);
                if (uVar7 < (uint)param_1[0xf]) {
                  param_1[0xe] = uVar7 + 1;
                  pwVar4 = _Str;
                  if (0xf < (uint)param_1[0xf]) {
                    pwVar4 = *(wchar_t **)_Str;
                  }
                  *(char *)((int)pwVar4 + uVar7) = (char)uVar2;
                  *(char *)((int)pwVar4 + uVar7 + 1) = '\0';
                }
                else {
LAB_10012f4d:
                  local_1c = local_1c & 0xffffff00;
                  FUN_10014ac0(_Str,uVar7,local_1c,(char)local_18);
                }
                goto LAB_10012f60;
              }
              goto switchD_10012c03_caseD_2f;
            }
          }
          param_1[0x10] = "invalid number; expected \'+\', \'-\', or digit after exponent";
          goto LAB_10012a5b;
        }
      }
switchD_10012c03_caseD_2f:
      param_1[4] = param_1[4] + -1;
      *(undefined1 *)(param_1 + 3) = 1;
      if (param_1[5] == 0) {
        if (param_1[6] != 0) {
          param_1[6] = param_1[6] + -1;
        }
      }
      else {
        param_1[5] = param_1[5] + -1;
      }
      if (uVar2 != 0xffffffff) {
        param_1[8] = param_1[8] + -1;
      }
      local_28 = (wchar_t *)0x0;
      piVar5 = __errno();
      *piVar5 = 0;
      if (local_24 == 5) {
        pwVar4 = _Str;
        if (0xf < (uint)param_1[0xf]) {
          pwVar4 = *(wchar_t **)_Str;
        }
        uVar10 = FID_conflict__strtoull((char *)pwVar4,(char **)&local_28,10);
        local_18 = (uint *)(uVar10 >> 0x20);
        piVar5 = __errno();
        if (*piVar5 == 0) {
          param_1[0x15] = local_18;
          param_1[0x14] = (int)uVar10;
          goto LAB_10012a5b;
        }
      }
      else if (local_24 == 6) {
        pwVar4 = _Str;
        if (0xf < (uint)param_1[0xf]) {
          pwVar4 = *(wchar_t **)_Str;
        }
        lVar11 = FID_conflict___strtoi64((char *)pwVar4,(char **)&local_28,10);
        local_18 = (uint *)((ulonglong)lVar11 >> 0x20);
        piVar5 = __errno();
        if (*piVar5 == 0) {
          param_1[0x13] = local_18;
          param_1[0x12] = (int)lVar11;
          goto LAB_10012a5b;
        }
      }
      if (0xf < (uint)param_1[0xf]) {
        _Str = *(wchar_t **)_Str;
      }
      dVar12 = FID_conflict__strtod(_Str,&local_28);
      *(double *)(param_1 + 0x16) = dVar12;
      goto LAB_10012a5b;
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x36:
    case 0x37:
    case 0x38:
    case 0x39:
      uVar2 = param_1[0xe];
      local_20 = param_1 + 0xf;
      local_18 = (uint *)CONCAT31(local_18._1_3_,cVar6);
      if (uVar2 < *local_20) {
        param_1[0xe] = uVar2 + 1;
        pwVar4 = _Str;
        if (0xf < *local_20) {
          pwVar4 = *(wchar_t **)_Str;
        }
        *(char *)((int)pwVar4 + uVar2) = cVar6;
        *(char *)((int)pwVar4 + uVar2 + 1) = '\0';
      }
      else {
        local_1c = local_1c & 0xffffff00;
        FUN_10014ac0(_Str,uVar7,local_1c,cVar6);
      }
      puVar8 = param_1 + 0xf;
LAB_10012ba0:
      param_1[4] = param_1[4] + 1;
      param_1[5] = param_1[5] + 1;
      if (*(char *)(param_1 + 3) == '\0') {
        uVar3 = (*(code *)**(undefined4 **)*param_1)();
        param_1[2] = uVar3;
      }
      else {
        *(undefined1 *)(param_1 + 3) = 0;
      }
      if (param_1[2] != -1) {
        puVar1 = (uint *)param_1[8];
        local_29 = (undefined1)param_1[2];
        if (puVar1 == (uint *)param_1[9]) {
          FUN_100174f0(param_1 + 7,puVar1,&local_29);
        }
        else {
          *(undefined1 *)puVar1 = local_29;
          param_1[8] = param_1[8] + 1;
        }
      }
      uVar2 = param_1[2];
      cVar6 = (char)uVar2;
      if (uVar2 == 10) goto LAB_10012fef;
      switch(uVar2) {
      case 0x2e:
        uVar2 = *local_20;
        break;
      default:
        goto switchD_10012c03_caseD_2f;
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
        uVar2 = param_1[0xe];
        uVar7 = *puVar8;
        local_18 = (uint *)CONCAT31(local_18._1_3_,cVar6);
        if (uVar2 < uVar7) {
          param_1[0xe] = uVar2 + 1;
          pwVar4 = _Str;
          if (0xf < uVar7) {
            pwVar4 = *(wchar_t **)_Str;
          }
          *(char *)((int)pwVar4 + uVar2) = cVar6;
          *(char *)((int)pwVar4 + uVar2 + 1) = '\0';
          puVar8 = local_20;
        }
        else {
          local_1c = local_1c & 0xffffff00;
          FUN_10014ac0(_Str,uVar2,local_1c,cVar6);
          puVar8 = local_20;
        }
        goto LAB_10012ba0;
      case 0x45:
      case 0x65:
        uVar2 = param_1[0xe];
        uVar7 = *puVar8;
        local_18 = (uint *)CONCAT31(local_18._1_3_,cVar6);
        if (uVar7 <= uVar2) goto LAB_10012dea;
        param_1[0xe] = uVar2 + 1;
        pwVar4 = _Str;
        if (0xf < uVar7) {
          pwVar4 = *(wchar_t **)_Str;
        }
        *(char *)((int)pwVar4 + uVar2) = cVar6;
        *(char *)((int)pwVar4 + uVar2 + 1) = '\0';
        goto LAB_10012dfc;
      }
LAB_10012c54:
      uVar7 = param_1[0xe];
      cVar6 = *(char *)(param_1 + 0x18);
      local_18 = (uint *)CONCAT31(local_18._1_3_,cVar6);
      if (uVar7 < uVar2) {
        param_1[0xe] = uVar7 + 1;
        pwVar4 = _Str;
        if (0xf < uVar2) {
          pwVar4 = *(wchar_t **)_Str;
        }
        *(char *)((int)pwVar4 + uVar7 + 1) = '\0';
        *(char *)((int)pwVar4 + uVar7) = cVar6;
      }
      else {
        local_1c = local_1c & 0xffffff00;
        FUN_10014ac0(_Str,uVar7,local_1c,cVar6);
      }
      param_1[4] = param_1[4] + 1;
      param_1[5] = param_1[5] + 1;
      local_24 = 7;
      if (*(char *)(param_1 + 3) == '\0') {
        uVar3 = (*(code *)**(undefined4 **)*param_1)();
        param_1[2] = uVar3;
      }
      else {
        *(undefined1 *)(param_1 + 3) = 0;
      }
      if (param_1[2] != -1) {
        puVar8 = (uint *)param_1[8];
        local_29 = (undefined1)param_1[2];
        if (puVar8 == (uint *)param_1[9]) {
          FUN_100174f0(param_1 + 7,puVar8,&local_29);
        }
        else {
          *(undefined1 *)puVar8 = local_29;
          param_1[8] = param_1[8] + 1;
        }
      }
      uVar2 = param_1[2];
      if (uVar2 == 10) {
        param_1[6] = param_1[6] + 1;
        param_1[5] = 0;
      }
      else {
        switch(uVar2) {
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
          uVar7 = param_1[0xe];
          uVar9 = param_1[0xf];
          local_18 = (uint *)CONCAT31(local_18._1_3_,(char)uVar2);
          if (uVar7 < uVar9) goto LAB_10012da9;
LAB_10012d1a:
          local_1c = local_1c & 0xffffff00;
          FUN_10014ac0(_Str,uVar2,local_1c,(char)local_18);
LAB_10012d30:
          param_1[4] = param_1[4] + 1;
          param_1[5] = param_1[5] + 1;
          if (*(char *)(param_1 + 3) == '\0') {
            uVar3 = (*(code *)**(undefined4 **)*param_1)();
            param_1[2] = uVar3;
          }
          else {
            *(undefined1 *)(param_1 + 3) = 0;
          }
          if (param_1[2] != -1) {
            puVar8 = (uint *)param_1[8];
            local_29 = (undefined1)param_1[2];
            if (puVar8 == (uint *)param_1[9]) {
              FUN_100174f0(param_1 + 7,puVar8,&local_29);
            }
            else {
              *(undefined1 *)puVar8 = local_29;
              param_1[8] = param_1[8] + 1;
            }
          }
          uVar2 = param_1[2];
          if (uVar2 != 10) {
            switch(uVar2) {
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
              goto switchD_10012d91_caseD_30;
            default:
              goto switchD_10012c03_caseD_2f;
            case 0x45:
            case 0x65:
              goto switchD_10012d91_caseD_45;
            }
          }
          goto LAB_10012fef;
        }
      }
      param_1[0x10] = "invalid number; expected digit after \'.\'";
      goto LAB_10012a5b;
    }
  }
  param_1[0x10] = "invalid number; expected digit after \'-\'";
LAB_10012a5b:
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
switchD_10012d91_caseD_30:
  uVar7 = param_1[0xe];
  uVar9 = param_1[0xf];
  local_18 = (uint *)CONCAT31(local_18._1_3_,(char)uVar2);
  if (uVar9 <= uVar7) goto LAB_10012d1a;
LAB_10012da9:
  param_1[0xe] = uVar7 + 1;
  pwVar4 = _Str;
  if (0xf < uVar9) {
    pwVar4 = *(wchar_t **)_Str;
  }
  *(char *)((int)pwVar4 + uVar7) = (char)uVar2;
  *(char *)((int)pwVar4 + uVar7 + 1) = '\0';
  goto LAB_10012d30;
}


// FUNCTION_END

// FUNCTION_START: FUN_100131f0 @ 100131f0