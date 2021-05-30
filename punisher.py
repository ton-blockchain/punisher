#!/usr/bin/env python3
# -*- coding: utf_8 -*-

# This script is a crutch for those who have not installed mytonctrl
# Full slashing version is available inside mytoncore.py (you need to install mytonctrl in full mode)
# Details of the full slashing process: Complaints-HOWTO.txt

# fix me:
lite_client = "/usr/bin/ton/lite-client/lite-client"
config = "/usr/bin/ton/lite-client/ton-lite-client-test1.config.json"
fift = "/usr/bin/ton/crypto/fift"
fiftpath = "/usr/src/ton/crypto/fift/lib/:/usr/src/ton/crypto/smartcont/"
validator_console = "/usr/bin/ton/validator-engine-console/validator-engine-console"
vc_key = "/usr/bin/ton/validator-engine-console/client"
vc_pubkey = "/usr/bin/ton/validator-engine-console/server.pub"
vc_addr = "127.0.0.1:22229" # netstat -ntlup
validator_wallet_name = "/home/ton/.local/share/mytoncore/wallets/validator_wallet_001"
validator_wallet_addr = "kf9X6ObXojpUZza3NiS2TnRJ4KR7ler8cOjMRBt_swy4QiYp"
adnl_addr = "EADD038C8B931BFC802E6725D57581570630C55AEF7181C8748C4A8F7907CDF7"


import os
import time
import json
import crc16
import base64
import struct
import subprocess

config32 = None
config34 = None


class Wallet:
	def __init__(self):
		self.name = None
		self.path = None
		self.addrFilePath = None
		self.privFilePath = None
		self.bocFilePath = None
		self.fullAddr = None
		self.workchain = None
		self.addr_hex = None
		self.addr = None
		self.addr_init = None
		self.oldseqno = None
		self.account = None
		self.subwallet = None
		self.v = None
	#end define

	def Refresh(self):
		buff = self.fullAddr.split(':')
		self.workchain = buff[0]
		self.addr_hex = buff[1]
		self.privFilePath = self.path + ".pk"
		if self.v == "v1":
			self.addrFilePath = self.path + ".addr"
			self.bocFilePath = self.path + "-query.boc"
		elif self.v == "hw":
			self.addrFilePath = self.path + str(self.subwallet) + ".addr"
			self.bocFilePath = self.path + str(self.subwallet) + "-query.boc"
	#end define

	def Delete(self):
		os.remove(self.addrFilePath)
		os.remove(self.privFilePath)
	#end define
#end class

def LiteClientCmd(cmd):
	args = [lite_client, "--global-config", config, "--verbosity", "0", "--cmd", cmd]
	ex = None
	for i in range(3):
		try:
			process = subprocess.run(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
		except: pass
	output = process.stdout.decode("utf-8")
	err = process.stderr.decode("utf-8")
	if len(err) > 0:
		print("LiteClientCmd args: {args}".format(args=args))
		raise Exception("LiteClient error: {err}".format(err=err))
	return output
#end define

def ValidatorConsoleCmd(cmd):
	args = [validator_console, "-k", vc_key, "-p", vc_pubkey, "-a", vc_addr, "-v", "0", "--cmd", cmd]
	for i in range(3):
		try:
			process = subprocess.run(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
		except: pass
	output = process.stdout.decode("utf-8")
	err = process.stderr.decode("utf-8")
	if len(err) > 0:
		print("ValidatorConsoleCmd args: {args}".format(args=args))
		raise Exception("ValidatorConsoleCmd error: {err}".format(err=err))
	return output
#end define

def FiftCmd(args):
	for i in range(len(args)):
		args[i] = str(args[i])
	args = [fift, "-I", fiftpath, "-s"] + args
	for i in range(3):
		try:
			process = subprocess.run(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
		except: pass
	output = process.stdout.decode("utf-8")
	err = process.stderr.decode("utf-8")
	if len(err) > 0:
		print("FiftCmd args: {args}".format(args=args))
		raise Exception("FiftCmd error: {err}".format(err=err))
	return output
#end define

def GetTimestamp():
	return int(time.time())
#end define

def GetElectionId():
	config32 = GetConfig32()
	return config32["startWorkTime"]
#end define

def GetValidatorIndex():
	adnlAddr = adnl_addr
	config34 = GetConfig34()
	validators = config34.get("validators")
	index = 0
	for validator in validators:
		searchAdnlAddr = validator.get("adnlAddr")
		if adnlAddr == searchAdnlAddr:
			return index
		index += 1
	print("GetValidatorIndex warning: index not found.")
	return -1
#end define

def GetConfig32():
	global config32
	if config32:
		return config32
	config32 = dict()
	result = LiteClientCmd("getconfig 32")
	config32["totalValidators"] = int(Pars(result, "total:", ' '))
	config32["startWorkTime"] = int(Pars(result, "utime_since:", ' '))
	config32["endWorkTime"] = int(Pars(result, "utime_until:", ' '))
	lines = result.split('\n')
	validators = list()
	for line in lines:
		if "public_key:" in line:
			validatorAdnlAddr = Pars(line, "adnl_addr:x", ')')
			pubkey = Pars(line, "pubkey:x", ')')
			if config32["totalValidators"] > 1:
				validatorWeight = int(Pars(line, "weight:", ' '))
			else:
				validatorWeight = int(Pars(line, "weight:", ')'))
			buff = dict()
			buff["adnlAddr"] = validatorAdnlAddr
			buff["pubkey"] = pubkey
			buff["weight"] = validatorWeight
			validators.append(buff)
	config32["validators"] = validators
	return config32
#end define

def GetConfig34():
	global config34
	if config34:
		return config34
	config34 = dict()
	result = LiteClientCmd("getconfig 34")
	config34["totalValidators"] = int(Pars(result, "total:", ' '))
	config34["startWorkTime"] = int(Pars(result, "utime_since:", ' '))
	config34["endWorkTime"] = int(Pars(result, "utime_until:", ' '))
	config34["totalWeight"] = int(Pars(result, "total_weight:", ' '))
	lines = result.split('\n')
	validators = list()
	for line in lines:
		if "public_key:" in line:
			validatorAdnlAddr = Pars(line, "adnl_addr:x", ')')
			pubkey = Pars(line, "pubkey:x", ')')
			if config34["totalValidators"] > 1:
				validatorWeight = int(Pars(line, "weight:", ' '))
			else:
				validatorWeight = int(Pars(line, "weight:", ')'))
			buff = dict()
			buff["adnlAddr"] = validatorAdnlAddr
			buff["pubkey"] = pubkey
			buff["weight"] = validatorWeight
			validators.append(buff)
	config34["validators"] = validators
	return config34
#end define

def Pars(text, search, search2=None):
	if search is None or text is None:
		return None
	if search not in text:
		return None
	text = text[text.find(search) + len(search):]
	if search2 is not None and search2 in text:
		text = text[:text.find(search2)]
	return text
#end define

def GetValidatorKey():
	data = GetConfigFromValidator()
	validators = data["validators"]
	for validator in validators:
		validatorId = validator["id"]
		key_bytes = base64.b64decode(validatorId)
		validatorKey = key_bytes.hex().upper()
		timestamp = GetTimestamp()
		if timestamp > validator["election_date"]:
			return validatorKey
	raise Exception("GetValidatorKey error: validator key not found. Are you sure you are a validator?")
#end define

def GetConfigFromValidator():
	result = ValidatorConsoleCmd("getconfig")
	string = Pars(result, "---------", "--------")
	vconfig = json.loads(string)
	return vconfig
#end define

def GetPubKeyBase64(key):
	result = ValidatorConsoleCmd("exportpub " + key)
	validatorPubkey_b64 = Pars(result, "got public key: ", '\n')
	return validatorPubkey_b64
#end define

def SaveComplaints(electionId):
	filePrefix = "/tmp/scp_"
	cmd = "savecomplaints {electionId} {filePrefix}".format(electionId=electionId, filePrefix=filePrefix)
	result = LiteClientCmd(cmd)
	lines = result.split('\n')
	complaintsHashes = list()
	for line in lines:
		if "SAVE_COMPLAINT" in line:
			buff = line.split('\t')
			chash = buff[2]
			validatorPubkey = buff[3]
			createdTime = buff[4]
			filePath = buff[5]
			ok = CheckComplaint(filePath)
			if ok is True:
				complaintsHashes.append(chash)
	return complaintsHashes
#end define

def CheckComplaint(filePath):
	cmd = "loadproofcheck {filePath}".format(filePath=filePath)
	result = LiteClientCmd(cmd)
	lines = result.split('\n')
	ok = False
	for line in lines:
		if "COMPLAINT_VOTE_FOR" in line:
			buff = line.split('\t')
			chash = buff[1]
			ok_buff = buff[2]
			if ok_buff == "YES":
				ok = True
	return ok
#end define

def Result2List(text):
	buff = Pars(text, "result:", "\n")
	if buff is None or "error" in buff:
		return
	buff = buff.replace(')', ']')
	buff = buff.replace('(', '[')
	buff = buff.replace(']', ' ] ')
	buff = buff.replace('[', ' [ ')
	arr = buff.split()
	
	# Get good raw data
	output = ""
	arrLen = len(arr)
	for i in range(arrLen):
		item = arr[i]
		# get next item
		if i+1 < arrLen:
			nextItem = arr[i+1]
		else:
			nextItem = None
		# add item to output
		if item == '[':
			output += item
		elif nextItem == ']':
			output += item
		elif '{' in item or '}' in item:
			output += "\"{item}\", ".format(item=item)
		elif i+1 == arrLen:
			output += item
		else:
			output += item + ', '
	#end for
	data = json.loads(output)
	return data
#end define

def GetComplaints(electionId):
	complaints = dict()
	fullElectorAddr = GetFullElectorAddr()
	cmd = "runmethodfull {fullElectorAddr} list_complaints {electionId}".format(fullElectorAddr=fullElectorAddr, electionId=electionId)
	result = LiteClientCmd(cmd)
	rawComplaints = Result2List(result)
	if rawComplaints is None:
		return complaints
	rawComplaints = rawComplaints[0]
	config34 = GetConfig34()
	totalWeight = config34.get("totalWeight")

	# Get json
	for complaint in rawComplaints:
		if len(complaint) == 0:
			continue
		chash = complaint[0]
		subdata = complaint[1]

		# Create dict
		# parser from: https://github.com/ton-blockchain/ton/blob/dab7ee3f9794db5a6d32c895dbc2564f681d9126/crypto/smartcont/elector-code.fc#L1149
		item = dict()
		buff = subdata[0] # *complaint*
		item["electionId"] = electionId
		item["hash"] = chash
		pubkey = Dec2HexAddr(buff[0]) # *validator_pubkey*
		adnl = GetAdnlFromPubkey(pubkey)
		item["pubkey"] = pubkey
		item["adnl"] = adnl
		item["description"] = buff[1] # *description*
		item["createdTime"] = buff[2] # *created_at*
		item["severity"] = buff[3] # *severity*
		rewardAddr = buff[4]
		rewardAddr = "-1:" + Dec2HexAddr(rewardAddr)
		rewardAddr = HexAddr2Base64Addr(rewardAddr)
		item["rewardAddr"] = rewardAddr # *reward_addr*
		item["paid"] = buff[5] # *paid*
		suggestedFine = buff[6] # *suggested_fine*
		item["suggestedFine"] = ng2g(suggestedFine)
		item["suggestedFinePart"] = buff[7] # *suggested_fine_part*
		votedValidators = subdata[1] # *voters_list*
		item["votedValidators"] = votedValidators
		item["vsetId"] = subdata[2] # *vset_id*
		weightRemaining = subdata[3] # *weight_remaining*
		requiredWeight = totalWeight * 2 / 3
		if len(votedValidators) == 0:
			weightRemaining = requiredWeight
		availableWeight = requiredWeight - weightRemaining
		item["weightRemaining"] = weightRemaining
		item["approvedPercent"] = round(availableWeight / totalWeight * 100, 3)
		item["isPassed"] = (weightRemaining < 0)
		pseudohash = pubkey + str(electionId)
		item["pseudohash"] = pseudohash
		complaints[pseudohash] = item
	#end for
	return complaints
#end define

def HexAddr2Base64Addr(fullAddr, bounceable=True, testnet=True):
	buff = fullAddr.split(':')
	workchain = int(buff[0])
	addr_hex = buff[1]
	if len(addr_hex) != 64:
		raise Exeption("HexAddr2Base64Addr error: Invalid length of hexadecimal address")
	#end if

	# Create base64 address
	b = bytearray(36)
	b[0] = 0x51 - bounceable * 0x40 + testnet * 0x80
	b[1] = workchain % 256
	b[2:34] = bytearray.fromhex(addr_hex)
	buff = bytes(b[:34])
	crc = crc16.crc16xmodem(buff)
	b[34] = crc >> 8
	b[35] = crc & 0xff
	result = base64.b64encode(b)
	result = result.decode()
	result = result.replace('+', '-')
	result = result.replace('/', '_')
	return result
#end define

def GetAdnlFromPubkey(inputPubkey):
	config32 = GetConfig32()
	validators = config32["validators"]
	for validator in validators:
		adnl = validator["adnlAddr"]
		pubkey = validator["pubkey"]
		if pubkey == inputPubkey:
			return adnl
#end define

def VoteComplaint(electionId, complaintHash):
	complaintHash = int(complaintHash)
	fullElectorAddr = GetFullElectorAddr()
	walletName = validator_wallet_name
	wallet = GetLocalWallet(walletName)
	validatorKey = GetValidatorKey()
	validatorPubkey_b64 = GetPubKeyBase64(validatorKey)
	validatorIndex = GetValidatorIndex()
	complaint = GetComplaint(electionId, complaintHash)
	votedValidators = complaint.get("votedValidators")
	if validatorIndex in votedValidators:
		print("Complaint already has been voted")
		return
	var1 = CreateComplaintRequest(electionId, complaintHash, validatorIndex)
	validatorSignature = GetValidatorSignature(validatorKey, var1)
	resultFilePath = SignComplaintVoteRequestWithValidator(complaintHash, electionId, validatorIndex, validatorPubkey_b64, validatorSignature)
	resultFilePath = SignFileWithWallet(wallet, resultFilePath, fullElectorAddr, 1.41)
	SendFile(resultFilePath, wallet)
#end define

def SendFile(filePath, wallet):
	if not os.path.isfile(filePath):
		raise Exception("SendFile error: no such file '{filePath}'".format(filePath=filePath))
	wallet.oldseqno = GetSeqno(wallet)
	result = LiteClientCmd("sendfile " + filePath)
	WaitTransaction(wallet)
	os.remove(filePath)
#end define

def WaitTransaction(wallet):
	for i in range(10): # wait 30 sec
		time.sleep(3)
		seqno = GetSeqno(wallet)
		if seqno != wallet.oldseqno:
			return
	raise Exception("WaitTransaction error: time out")
#end define

def SignFileWithWallet(wallet, filePath, addr, gram):
	seqno = GetSeqno(wallet)
	resultFilePath = "/tmp/result"
	args = ["wallet.fif", wallet.path, addr, seqno, gram, "-B", filePath, resultFilePath]
	result = FiftCmd(args)
	resultFilePath = Pars(result, "Saved to file ", ")")
	return resultFilePath
#end define

def GetSeqno(wallet):
	cmd = "runmethod {addr} seqno".format(addr=wallet.addr)
	result = LiteClientCmd(cmd)
	if "cannot run any methods" in result:
		return None
	if "result" not in result:
		return 0
	seqno = GetVarFromWorkerOutput(result, "result")
	seqno = seqno.replace(' ', '')
	seqno = Pars(seqno, '[', ']')
	seqno = int(seqno)
	return seqno
#end define

def SignComplaintVoteRequestWithValidator(complaintHash, electionId, validatorIndex, validatorPubkey_b64, validatorSignature):
	fileName = "/tmp/msb.boc"
	args = ["complaint-vote-signed.fif", validatorIndex, electionId, complaintHash, validatorPubkey_b64, validatorSignature, fileName]
	result = FiftCmd(args)
	fileName = Pars(result, "Saved to file ", '\n')
	return fileName
#end define

def GetValidatorSignature(validatorKey, var1):
	cmd = "sign {validatorKey} {var1}".format(validatorKey=validatorKey, var1=var1)
	result = ValidatorConsoleCmd(cmd)
	validatorSignature = Pars(result, "got signature ", '\n')
	return validatorSignature
#end define

def CreateComplaintRequest(electionId, complaintHash, validatorIndex):
	fileName = "/tmp/cvr.boc"
	args = ["complaint-vote-req.fif", validatorIndex, electionId, complaintHash, fileName]
	result = FiftCmd(args)
	fileName = Pars(result, "Saved to file ", '\n')
	resultList = result.split('\n')
	i = 0
	start_index = 0
	for item in resultList:
		if "Creating a request to vote for complaint" in item:
			start_index = i
		i += 1
	var1 = resultList[start_index + 1]
	var2 = resultList[start_index + 2] # var2 not using
	return var1
#end define

def GetComplaint(electionId, complaintHash):
	complaints = GetComplaints(electionId)
	for key, item in complaints.items():
		if complaintHash == item.get("hash"):
			return item
	raise Exception("GetComplaint error: complaint not found.")
#end define

def GetLocalWallet(walletName):
	if walletName is None:
		return None
	filePath = walletName
	if (".addr" in filePath):
		filePath = filePath.replace(".addr", '')
	if (".pk" in filePath):
		filePath = filePath.replace(".pk", '')
	if os.path.isfile(filePath + ".pk") == False:
		raise Exception("GetWalletFromFile error: Private key not found: " + filePath)
	#end if

	# Create wallet object
	wallet = Wallet()
	wallet.v = "v1"
	wallet.path = filePath
	if '/' in filePath:
		wallet.name = filePath[filePath.rfind('/')+1:]
	else:
		wallet.name = filePath
	#end if

	addrFilePath = filePath + ".addr"
	AddrFile2Wallet(wallet, addrFilePath)
	return wallet
#end define

def AddrFile2Wallet(wallet, addrFilePath):
	file = open(addrFilePath, "rb")
	data = file.read()
	addr_hex = data[:32].hex()
	workchain = struct.unpack("i", data[32:])[0]
	wallet.fullAddr = str(workchain) + ":" + addr_hex
	wallet.addr = HexAddr2Base64Addr(wallet.fullAddr)
	wallet.addr_init = HexAddr2Base64Addr(wallet.fullAddr, False)
	wallet.Refresh()
#end define

def GetFullElectorAddr():
	result = LiteClientCmd("getconfig 1")
	electorAddr_hex = GetVarFromWorkerOutput(result, "elector_addr:x")
	fullElectorAddr = "-1:{electorAddr_hex}".format(electorAddr_hex=electorAddr_hex)
	return fullElectorAddr
#end define

def GetVarFromWorkerOutput(text, search):
	if ':' not in search:
		search += ':'
	if search is None or text is None:
		return None
	if search not in text:
		return None
	start = text.find(search) + len(search)
	count = 0
	bcount = 0
	textLen = len(text)
	end = textLen
	for i in range(start, textLen):
		letter = text[i]
		if letter == '(':
			count += 1
			bcount += 1
		elif letter == ')':
			count -= 1
		if letter == ')' and count < 1:
			end = i + 1
			break
		elif letter == '\n' and count < 1:
			end = i
			break
	result = text[start:end]
	if count != 0 and bcount == 0:
		result = result.replace(')', '')
	return result
#end define

def Dec2HexAddr(dec):
	h = dec2hex(dec)
	hu = h.upper()
	h64 = hu.rjust(64, "0")
	return h64
#end define

def dec2hex(dec):
	h = hex(dec)[2:]
	if len(h) % 2 > 0:
		h = '0' + h
	return h
#end define

def ng2g(ng):
	return int(ng)/10**9
#end define


###
### Start of the program
###

print("start punisher.py")
electionId = GetElectionId()
complaintsHashes = SaveComplaints(electionId)
complaints = GetComplaints(electionId)

for key, item in complaints.items():
	complaintHash = item.get("hash")
	complaintHash_hex = Dec2HexAddr(complaintHash)
	if complaintHash_hex in complaintsHashes:
		VoteComplaint(electionId, complaintHash)
	os.system("rm -rf /tmp/cvr.boc")
	os.system("rm -rf /tmp/msb.boc")
	os.system("rm -rf /tmp/result.boc")
#end for

os.system("rm -rf /tmp/scp_*.boc")
print("end punisher.py")
