int * __thiscall FUN_1001b8f0(void *this,int *param_1)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  int *piVar4;
  int *piVar5;
  char cVar6;
  int *piVar7;
  int *piVar8;
  
  piVar4 = param_1;
  std::
  _Tree_unchecked_const_iterator<class_std::_Tree_val<struct_std::_Tree_simple_types<unsigned_int>_>,struct_std::_Iterator_base0>
  ::operator++((_Tree_unchecked_const_iterator<class_std::_Tree_val<struct_std::_Tree_simple_types<unsigned_int>_>,struct_std::_Iterator_base0>
                *)&param_1);
  piVar5 = (int *)*piVar4;
  piVar7 = (int *)piVar4[2];
  if (((*(char *)((int)piVar5 + 0xd) == '\0') &&
      (piVar7 = piVar5, *(char *)(piVar4[2] + 0xd) == '\0')) &&
     (piVar7 = (int *)param_1[2], param_1 != piVar4)) {
    piVar5[1] = (int)param_1;
    *param_1 = *piVar4;
    piVar5 = param_1;
    if (param_1 != (int *)piVar4[2]) {
      piVar5 = (int *)param_1[1];
      if (*(char *)((int)piVar7 + 0xd) == '\0') {
        piVar7[1] = (int)piVar5;
      }
      *piVar5 = (int)piVar7;
      param_1[2] = piVar4[2];
      *(int **)(piVar4[2] + 4) = param_1;
    }
                    /* WARNING: Load size is inaccurate */
    if (*(int **)(*this + 4) == piVar4) {
      *(int **)(*this + 4) = param_1;
    }
    else {
      piVar8 = (int *)piVar4[1];
      if ((int *)*piVar8 == piVar4) {
        *piVar8 = (int)param_1;
      }
      else {
        piVar8[2] = (int)param_1;
      }
    }
    cVar6 = (char)param_1[3];
    param_1[1] = piVar4[1];
    *(char *)(param_1 + 3) = (char)piVar4[3];
    *(char *)(piVar4 + 3) = cVar6;
  }
  else {
    piVar5 = (int *)piVar4[1];
    if (*(char *)((int)piVar7 + 0xd) == '\0') {
      piVar7[1] = (int)piVar5;
    }
                    /* WARNING: Load size is inaccurate */
    if (*(int **)(*this + 4) == piVar4) {
      *(int **)(*this + 4) = piVar7;
    }
    else if ((int *)*piVar5 == piVar4) {
      *piVar5 = (int)piVar7;
    }
    else {
      piVar5[2] = (int)piVar7;
    }
                    /* WARNING: Load size is inaccurate */
    if ((int *)**this == piVar4) {
      piVar8 = piVar5;
      if (*(char *)((int)piVar7 + 0xd) == '\0') {
        cVar6 = *(char *)(*piVar7 + 0xd);
        piVar2 = (int *)*piVar7;
        piVar8 = piVar7;
        while (piVar3 = piVar2, cVar6 == '\0') {
          piVar2 = (int *)*piVar3;
          cVar6 = *(char *)((int)piVar2 + 0xd);
          piVar8 = piVar3;
        }
      }
      **this = (int)piVar8;
    }
                    /* WARNING: Load size is inaccurate */
    iVar1 = *this;
    if (*(int **)(iVar1 + 8) == piVar4) {
      if (*(char *)((int)piVar7 + 0xd) != '\0') {
        *(int **)(iVar1 + 8) = piVar5;
        cVar6 = (char)piVar4[3];
        goto LAB_1001ba22;
      }
      cVar6 = *(char *)(piVar7[2] + 0xd);
      piVar8 = (int *)piVar7[2];
      piVar2 = piVar7;
      while (piVar3 = piVar8, cVar6 == '\0') {
        piVar8 = (int *)piVar3[2];
        cVar6 = *(char *)((int)piVar8 + 0xd);
        piVar2 = piVar3;
      }
      *(int **)(iVar1 + 8) = piVar2;
    }
    cVar6 = (char)piVar4[3];
  }
LAB_1001ba22:
  if (cVar6 == '\x01') {
                    /* WARNING: Load size is inaccurate */
    if (piVar7 != *(int **)(*this + 4)) {
      while (piVar8 = piVar5, (char)piVar7[3] == '\x01') {
        piVar5 = (int *)*piVar8;
        if (piVar7 == piVar5) {
          piVar5 = (int *)piVar8[2];
          if ((char)piVar5[3] == '\0') {
            *(undefined1 *)(piVar5 + 3) = 1;
            piVar5 = (int *)piVar8[2];
            *(undefined1 *)(piVar8 + 3) = 0;
            piVar8[2] = *piVar5;
            if (*(char *)(*piVar5 + 0xd) == '\0') {
              *(int **)(*piVar5 + 4) = piVar8;
            }
            piVar5[1] = piVar8[1];
                    /* WARNING: Load size is inaccurate */
            if (piVar8 == *(int **)(*this + 4)) {
              *(int **)(*this + 4) = piVar5;
            }
            else {
              piVar2 = (int *)piVar8[1];
              if (piVar8 == (int *)*piVar2) {
                *piVar2 = (int)piVar5;
              }
              else {
                piVar2[2] = (int)piVar5;
              }
            }
            *piVar5 = (int)piVar8;
            piVar8[1] = (int)piVar5;
            piVar5 = (int *)piVar8[2];
          }
          if (*(char *)((int)piVar5 + 0xd) == '\0') {
            if ((*(char *)(*piVar5 + 0xc) != '\x01') || (*(char *)(piVar5[2] + 0xc) != '\x01')) {
              if (*(char *)(piVar5[2] + 0xc) == '\x01') {
                *(undefined1 *)(*piVar5 + 0xc) = 1;
                iVar1 = *piVar5;
                *(undefined1 *)(piVar5 + 3) = 0;
                *piVar5 = *(int *)(iVar1 + 8);
                if (*(char *)(*(int *)(iVar1 + 8) + 0xd) == '\0') {
                  *(int **)(*(int *)(iVar1 + 8) + 4) = piVar5;
                }
                *(int *)(iVar1 + 4) = piVar5[1];
                    /* WARNING: Load size is inaccurate */
                if (piVar5 == *(int **)(*this + 4)) {
                  *(int *)(*this + 4) = iVar1;
                }
                else {
                  piVar2 = (int *)piVar5[1];
                  if (piVar5 == (int *)piVar2[2]) {
                    piVar2[2] = iVar1;
                  }
                  else {
                    *piVar2 = iVar1;
                  }
                }
                *(int **)(iVar1 + 8) = piVar5;
                piVar5[1] = iVar1;
                piVar5 = (int *)piVar8[2];
              }
              *(char *)(piVar5 + 3) = (char)piVar8[3];
              *(undefined1 *)(piVar8 + 3) = 1;
              *(undefined1 *)(piVar5[2] + 0xc) = 1;
              piVar5 = (int *)piVar8[2];
              piVar8[2] = *piVar5;
              if (*(char *)(*piVar5 + 0xd) == '\0') {
                *(int **)(*piVar5 + 4) = piVar8;
              }
              piVar5[1] = piVar8[1];
                    /* WARNING: Load size is inaccurate */
              if (piVar8 == *(int **)(*this + 4)) {
                *(int **)(*this + 4) = piVar5;
                *piVar5 = (int)piVar8;
                piVar8[1] = (int)piVar5;
              }
              else {
                piVar2 = (int *)piVar8[1];
                if (piVar8 == (int *)*piVar2) {
                  *piVar2 = (int)piVar5;
                  *piVar5 = (int)piVar8;
                  piVar8[1] = (int)piVar5;
                }
                else {
                  piVar2[2] = (int)piVar5;
                  *piVar5 = (int)piVar8;
                  piVar8[1] = (int)piVar5;
                }
              }
              break;
            }
LAB_1001bb6e:
            *(undefined1 *)(piVar5 + 3) = 0;
          }
        }
        else {
          if ((char)piVar5[3] == '\0') {
            *(undefined1 *)(piVar5 + 3) = 1;
            iVar1 = *piVar8;
            *(undefined1 *)(piVar8 + 3) = 0;
            *piVar8 = *(int *)(iVar1 + 8);
            if (*(char *)(*(int *)(iVar1 + 8) + 0xd) == '\0') {
              *(int **)(*(int *)(iVar1 + 8) + 4) = piVar8;
            }
            *(int *)(iVar1 + 4) = piVar8[1];
                    /* WARNING: Load size is inaccurate */
            if (piVar8 == *(int **)(*this + 4)) {
              *(int *)(*this + 4) = iVar1;
            }
            else {
              piVar5 = (int *)piVar8[1];
              if (piVar8 == (int *)piVar5[2]) {
                piVar5[2] = iVar1;
              }
              else {
                *piVar5 = iVar1;
              }
            }
            *(int **)(iVar1 + 8) = piVar8;
            piVar8[1] = iVar1;
            piVar5 = (int *)*piVar8;
          }
          if (*(char *)((int)piVar5 + 0xd) == '\0') {
            if ((*(char *)(piVar5[2] + 0xc) == '\x01') && (*(char *)(*piVar5 + 0xc) == '\x01'))
            goto LAB_1001bb6e;
            if (*(char *)(*piVar5 + 0xc) == '\x01') {
              *(undefined1 *)(piVar5[2] + 0xc) = 1;
              piVar2 = (int *)piVar5[2];
              *(undefined1 *)(piVar5 + 3) = 0;
              piVar5[2] = *piVar2;
              if (*(char *)(*piVar2 + 0xd) == '\0') {
                *(int **)(*piVar2 + 4) = piVar5;
              }
              piVar2[1] = piVar5[1];
                    /* WARNING: Load size is inaccurate */
              if (piVar5 == *(int **)(*this + 4)) {
                *(int **)(*this + 4) = piVar2;
              }
              else {
                piVar3 = (int *)piVar5[1];
                if (piVar5 == (int *)*piVar3) {
                  *piVar3 = (int)piVar2;
                }
                else {
                  piVar3[2] = (int)piVar2;
                }
              }
              *piVar2 = (int)piVar5;
              piVar5[1] = (int)piVar2;
              piVar5 = (int *)*piVar8;
            }
            *(char *)(piVar5 + 3) = (char)piVar8[3];
            *(undefined1 *)(piVar8 + 3) = 1;
            *(undefined1 *)(*piVar5 + 0xc) = 1;
            iVar1 = *piVar8;
            *piVar8 = *(int *)(iVar1 + 8);
            if (*(char *)(*(int *)(iVar1 + 8) + 0xd) == '\0') {
              *(int **)(*(int *)(iVar1 + 8) + 4) = piVar8;
            }
            *(int *)(iVar1 + 4) = piVar8[1];
                    /* WARNING: Load size is inaccurate */
            if (piVar8 == *(int **)(*this + 4)) {
              *(int *)(*this + 4) = iVar1;
              *(int **)(iVar1 + 8) = piVar8;
              piVar8[1] = iVar1;
            }
            else {
              piVar5 = (int *)piVar8[1];
              if (piVar8 == (int *)piVar5[2]) {
                piVar5[2] = iVar1;
                *(int **)(iVar1 + 8) = piVar8;
                piVar8[1] = iVar1;
              }
              else {
                *piVar5 = iVar1;
                *(int **)(iVar1 + 8) = piVar8;
                piVar8[1] = iVar1;
              }
            }
            break;
          }
        }
                    /* WARNING: Load size is inaccurate */
        piVar5 = (int *)piVar8[1];
        piVar7 = piVar8;
        if (piVar8 == *(int **)(*this + 4)) break;
      }
    }
    *(undefined1 *)(piVar7 + 3) = 1;
  }
  if (*(int *)((int)this + 4) != 0) {
    *(int *)((int)this + 4) = *(int *)((int)this + 4) + -1;
  }
  return piVar4;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001bcd0 @ 1001bcd0