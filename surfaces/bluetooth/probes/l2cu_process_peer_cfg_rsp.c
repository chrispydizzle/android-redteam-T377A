
void l2cu_process_peer_cfg_rsp(int param_1,int param_2,undefined4 param_3)

{
  uint uVar1;
  undefined4 uVar2;
  ushort uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  uint uVar6;
  bool bVar7;
  
  if ((*(char *)(param_2 + 6) != '\0') && (*(char *)(param_1 + 0x4a) != '\0')) {
    uVar2 = *(undefined4 *)(param_2 + 0xc);
    uVar4 = *(undefined4 *)(param_2 + 0x10);
    uVar5 = *(undefined4 *)(param_2 + 0x14);
    *(undefined4 *)(param_1 + 0x4c) = *(undefined4 *)(param_2 + 8);
    *(undefined4 *)(param_1 + 0x50) = uVar2;
    *(undefined4 *)(param_1 + 0x54) = uVar4;
    *(undefined4 *)(param_1 + 0x58) = uVar5;
    uVar2 = *(undefined4 *)(param_2 + 0x1c);
    *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_2 + 0x18);
    *(undefined4 *)(param_1 + 0x60) = uVar2;
  }
  if (*(char *)(param_2 + 0x24) != '\0') {
    uVar3 = (ushort)*(byte *)(param_2 + 0x26);
    uVar6 = (uint)*(byte *)(param_1 + 0x6b);
    bVar7 = uVar3 == 3;
    if (bVar7) {
      uVar3 = *(ushort *)(param_2 + 0x2a);
    }
    if (bVar7) {
      *(ushort *)(param_1 + 0xba) = uVar3;
      uVar3 = *(ushort *)(param_2 + 0x2c);
    }
    if (bVar7) {
      *(ushort *)(param_1 + 0xbc) = uVar3;
    }
    uVar1 = (uint)*(byte *)(param_2 + 0x27);
    if (uVar6 <= uVar1) {
      uVar1 = uVar6;
    }
    *(char *)(param_1 + 0xf9) = (char)(uVar1 / 3);
    if (4 < l2cb[0]) {
      LogMsg(0x80004,
             "l2cu_process_peer_cfg_rsp(): peer tx_win_sz: %d, our tx_win_sz: %d, max_held_acks: %d"
             ,*(undefined *)(param_2 + 0x27),uVar6,uVar1 / 3,param_2,param_3);
    }
  }
  return;
}

