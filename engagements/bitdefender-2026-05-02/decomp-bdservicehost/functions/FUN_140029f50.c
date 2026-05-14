longlong * FUN_140029f50(longlong *param_1,longlong *param_2)

{
  longlong lVar1;
  undefined8 *puVar2;
  longlong *plVar3;
  longlong *plVar4;
  longlong *plVar5;
  longlong *plVar6;
  char cVar7;
  longlong *plVar8;
  
  plVar4 = (longlong *)param_2[2];
  plVar8 = param_2 + 2;
  if (*(char *)((longlong)plVar4 + 0x19) == '\0') {
    cVar7 = *(char *)(*plVar4 + 0x19);
    plVar5 = (longlong *)*plVar4;
    while (cVar7 == '\0') {
      cVar7 = *(char *)(*plVar5 + 0x19);
      plVar4 = plVar5;
      plVar5 = (longlong *)*plVar5;
    }
  }
  else {
    cVar7 = *(char *)(param_2[1] + 0x19);
    plVar6 = (longlong *)param_2[1];
    plVar5 = param_2;
    while ((plVar4 = plVar6, cVar7 == '\0' && (plVar5 == (longlong *)plVar4[2]))) {
      cVar7 = *(char *)(plVar4[1] + 0x19);
      plVar6 = (longlong *)plVar4[1];
      plVar5 = plVar4;
    }
  }
  plVar5 = (longlong *)*param_2;
  plVar6 = (longlong *)*plVar8;
  if (((*(char *)((longlong)plVar5 + 0x19) == '\0') &&
      (plVar6 = plVar5, *(char *)(*plVar8 + 0x19) == '\0')) &&
     (plVar6 = (longlong *)plVar4[2], plVar4 != param_2)) {
    plVar5[1] = (longlong)plVar4;
    *plVar4 = *param_2;
    plVar5 = plVar4;
    if (plVar4 != (longlong *)*plVar8) {
      plVar5 = (longlong *)plVar4[1];
      if (*(char *)((longlong)plVar6 + 0x19) == '\0') {
        plVar6[1] = (longlong)plVar5;
      }
      *plVar5 = (longlong)plVar6;
      plVar4[2] = *plVar8;
      *(longlong **)(*plVar8 + 8) = plVar4;
    }
    if (*(longlong **)(*param_1 + 8) == param_2) {
      *(longlong **)(*param_1 + 8) = plVar4;
    }
    else {
      plVar8 = (longlong *)param_2[1];
      if ((longlong *)*plVar8 == param_2) {
        *plVar8 = (longlong)plVar4;
      }
      else {
        plVar8[2] = (longlong)plVar4;
      }
    }
    cVar7 = (char)plVar4[3];
    plVar4[1] = param_2[1];
    *(char *)(plVar4 + 3) = (char)param_2[3];
    *(char *)(param_2 + 3) = cVar7;
  }
  else {
    plVar5 = (longlong *)param_2[1];
    if (*(char *)((longlong)plVar6 + 0x19) == '\0') {
      plVar6[1] = (longlong)plVar5;
    }
    if (*(longlong **)(*param_1 + 8) == param_2) {
      *(longlong **)(*param_1 + 8) = plVar6;
    }
    else if ((longlong *)*plVar5 == param_2) {
      *plVar5 = (longlong)plVar6;
    }
    else {
      plVar5[2] = (longlong)plVar6;
    }
    if (*(longlong **)*param_1 == param_2) {
      plVar8 = plVar5;
      if (*(char *)((longlong)plVar6 + 0x19) == '\0') {
        cVar7 = *(char *)(*plVar6 + 0x19);
        plVar4 = (longlong *)*plVar6;
        plVar8 = plVar6;
        while (plVar3 = plVar4, cVar7 == '\0') {
          plVar4 = (longlong *)*plVar3;
          cVar7 = *(char *)((longlong)plVar4 + 0x19);
          plVar8 = plVar3;
        }
      }
      *(longlong **)*param_1 = plVar8;
    }
    lVar1 = *param_1;
    if (*(longlong **)(lVar1 + 0x10) == param_2) {
      if (*(char *)((longlong)plVar6 + 0x19) != '\0') {
        *(longlong **)(lVar1 + 0x10) = plVar5;
        cVar7 = (char)param_2[3];
        goto LAB_14002a0e5;
      }
      cVar7 = *(char *)(plVar6[2] + 0x19);
      plVar8 = (longlong *)plVar6[2];
      plVar4 = plVar6;
      while (plVar3 = plVar8, cVar7 == '\0') {
        plVar8 = (longlong *)plVar3[2];
        cVar7 = *(char *)((longlong)plVar8 + 0x19);
        plVar4 = plVar3;
      }
      *(longlong **)(lVar1 + 0x10) = plVar4;
    }
    cVar7 = (char)param_2[3];
  }
LAB_14002a0e5:
  if (cVar7 == '\x01') {
    if (plVar6 != *(longlong **)(*param_1 + 8)) {
      do {
        plVar8 = plVar5;
        if ((char)plVar6[3] != '\x01') break;
        plVar4 = (longlong *)*plVar8;
        if (plVar6 == plVar4) {
          plVar4 = (longlong *)plVar8[2];
          if ((char)plVar4[3] == '\0') {
            *(undefined1 *)(plVar4 + 3) = 1;
            plVar4 = (longlong *)plVar8[2];
            *(undefined1 *)(plVar8 + 3) = 0;
            plVar8[2] = *plVar4;
            if (*(char *)(*plVar4 + 0x19) == '\0') {
              *(longlong **)(*plVar4 + 8) = plVar8;
            }
            plVar4[1] = plVar8[1];
            if (plVar8 == *(longlong **)(*param_1 + 8)) {
              *(longlong **)(*param_1 + 8) = plVar4;
            }
            else {
              puVar2 = (undefined8 *)plVar8[1];
              if (plVar8 == (longlong *)*puVar2) {
                *puVar2 = plVar4;
              }
              else {
                puVar2[2] = plVar4;
              }
            }
            *plVar4 = (longlong)plVar8;
            plVar8[1] = (longlong)plVar4;
            plVar4 = (longlong *)plVar8[2];
          }
          if (*(char *)((longlong)plVar4 + 0x19) == '\0') {
            if ((*(char *)(*plVar4 + 0x18) != '\x01') || (*(char *)(plVar4[2] + 0x18) != '\x01')) {
              if (*(char *)(plVar4[2] + 0x18) == '\x01') {
                *(undefined1 *)(*plVar4 + 0x18) = 1;
                lVar1 = *plVar4;
                *(undefined1 *)(plVar4 + 3) = 0;
                *plVar4 = *(longlong *)(lVar1 + 0x10);
                if (*(char *)(*(longlong *)(lVar1 + 0x10) + 0x19) == '\0') {
                  *(longlong **)(*(longlong *)(lVar1 + 0x10) + 8) = plVar4;
                }
                *(longlong *)(lVar1 + 8) = plVar4[1];
                if (plVar4 == *(longlong **)(*param_1 + 8)) {
                  *(longlong *)(*param_1 + 8) = lVar1;
                }
                else {
                  plVar5 = (longlong *)plVar4[1];
                  if (plVar4 == (longlong *)plVar5[2]) {
                    plVar5[2] = lVar1;
                  }
                  else {
                    *plVar5 = lVar1;
                  }
                }
                *(longlong **)(lVar1 + 0x10) = plVar4;
                plVar4[1] = lVar1;
                plVar4 = (longlong *)plVar8[2];
              }
              *(char *)(plVar4 + 3) = (char)plVar8[3];
              *(undefined1 *)(plVar8 + 3) = 1;
              *(undefined1 *)(plVar4[2] + 0x18) = 1;
              plVar4 = (longlong *)plVar8[2];
              plVar8[2] = *plVar4;
              if (*(char *)(*plVar4 + 0x19) == '\0') {
                *(longlong **)(*plVar4 + 8) = plVar8;
              }
              plVar4[1] = plVar8[1];
              if (plVar8 == *(longlong **)(*param_1 + 8)) {
                *(longlong **)(*param_1 + 8) = plVar4;
                *plVar4 = (longlong)plVar8;
              }
              else {
                puVar2 = (undefined8 *)plVar8[1];
                if (plVar8 == (longlong *)*puVar2) {
                  *puVar2 = plVar4;
                  *plVar4 = (longlong)plVar8;
                }
                else {
                  puVar2[2] = plVar4;
                  *plVar4 = (longlong)plVar8;
                }
              }
LAB_14002a3bd:
              plVar8[1] = (longlong)plVar4;
              break;
            }
LAB_14002a264:
            *(undefined1 *)(plVar4 + 3) = 0;
          }
        }
        else {
          if ((char)plVar4[3] == '\0') {
            *(undefined1 *)(plVar4 + 3) = 1;
            lVar1 = *plVar8;
            *(undefined1 *)(plVar8 + 3) = 0;
            *plVar8 = *(longlong *)(lVar1 + 0x10);
            if (*(char *)(*(longlong *)(lVar1 + 0x10) + 0x19) == '\0') {
              *(longlong **)(*(longlong *)(lVar1 + 0x10) + 8) = plVar8;
            }
            *(longlong *)(lVar1 + 8) = plVar8[1];
            if (plVar8 == *(longlong **)(*param_1 + 8)) {
              *(longlong *)(*param_1 + 8) = lVar1;
            }
            else {
              plVar4 = (longlong *)plVar8[1];
              if (plVar8 == (longlong *)plVar4[2]) {
                plVar4[2] = lVar1;
              }
              else {
                *plVar4 = lVar1;
              }
            }
            *(longlong **)(lVar1 + 0x10) = plVar8;
            plVar8[1] = lVar1;
            plVar4 = (longlong *)*plVar8;
          }
          if (*(char *)((longlong)plVar4 + 0x19) == '\0') {
            if ((*(char *)(plVar4[2] + 0x18) != '\x01') || (*(char *)(*plVar4 + 0x18) != '\x01')) {
              if (*(char *)(*plVar4 + 0x18) == '\x01') {
                *(undefined1 *)(plVar4[2] + 0x18) = 1;
                plVar5 = (longlong *)plVar4[2];
                *(undefined1 *)(plVar4 + 3) = 0;
                plVar4[2] = *plVar5;
                if (*(char *)(*plVar5 + 0x19) == '\0') {
                  *(longlong **)(*plVar5 + 8) = plVar4;
                }
                plVar5[1] = plVar4[1];
                if (plVar4 == *(longlong **)(*param_1 + 8)) {
                  *(longlong **)(*param_1 + 8) = plVar5;
                }
                else {
                  puVar2 = (undefined8 *)plVar4[1];
                  if (plVar4 == (longlong *)*puVar2) {
                    *puVar2 = plVar5;
                  }
                  else {
                    puVar2[2] = plVar5;
                  }
                }
                *plVar5 = (longlong)plVar4;
                plVar4[1] = (longlong)plVar5;
                plVar4 = (longlong *)*plVar8;
              }
              *(char *)(plVar4 + 3) = (char)plVar8[3];
              *(undefined1 *)(plVar8 + 3) = 1;
              *(undefined1 *)(*plVar4 + 0x18) = 1;
              plVar4 = (longlong *)*plVar8;
              *plVar8 = plVar4[2];
              if (*(char *)(plVar4[2] + 0x19) == '\0') {
                *(longlong **)(plVar4[2] + 8) = plVar8;
              }
              plVar4[1] = plVar8[1];
              if (plVar8 == *(longlong **)(*param_1 + 8)) {
                *(longlong **)(*param_1 + 8) = plVar4;
              }
              else {
                puVar2 = (undefined8 *)plVar8[1];
                if (plVar8 == (longlong *)puVar2[2]) {
                  puVar2[2] = plVar4;
                }
                else {
                  *puVar2 = plVar4;
                }
              }
              plVar4[2] = (longlong)plVar8;
              goto LAB_14002a3bd;
            }
            goto LAB_14002a264;
          }
        }
        plVar5 = (longlong *)plVar8[1];
        plVar6 = plVar8;
      } while (plVar8 != *(longlong **)(*param_1 + 8));
    }
    *(undefined1 *)(plVar6 + 3) = 1;
  }
  if (param_1[1] != 0) {
    param_1[1] = param_1[1] + -1;
  }
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002a3f0 @ 14002a3f0