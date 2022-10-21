package main

import (
	"fmt"
	"os"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func main() {
	// 参数如何选择？
	// 1. 先假定数字的范围是[0,5000]
	// 2. 如果比较的范围选择[0, 2^32], 参数该如何选，对加密后的密文的大小影响有多大？
	paramDef := bfv.PN12QP109
	paramDef.LogN = 4
	params, err := bfv.NewParametersFromLiteral(paramDef)
	if err != nil {
		panic(err)
	}

	kgen := bfv.NewKeyGenerator(params)
	encoder := bfv.NewEncoder(params)
	sk, pk := kgen.GenKeyPair()
	encryptor := bfv.NewEncryptor(params, pk)
	decryptor := bfv.NewDecryptor(params, sk)
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{})

	data, _ := sk.MarshalBinary()
	os.WriteFile("sk.bin", data, 0644)
	data, _ = pk.MarshalBinary()
	os.WriteFile("pk.bin", data, 0644)

	// 输入比较的参数
	inputs := []uint64{9, 1, 17, 1000, 3197, 9812, 751}

	// 输入的参数是待比较的密文参数
	ciphertexts := make([]*bfv.Ciphertext, len(inputs))

	// 准备密文数据
	for i, v := range inputs {
		plaintext := bfv.NewPlaintext(params)
		encoder.Encode([]uint64{v}, plaintext)
		ciphertexts[i] = encryptor.EncryptNew(plaintext)
		data, err := ciphertexts[i].MarshalBinary()
		if err != nil {
			panic(err)
		}
		os.WriteFile(fmt.Sprintf("%d.bin", i), data, 0644)
		fmt.Printf("%d %d\n", i, len(data))
	}

	// 示例的求和操作，已实现
	ciphertext := bfv.NewCiphertext(params, 1)
	for i := range ciphertexts {
		evaluator.Add(ciphertext, ciphertexts[i], ciphertext) // 求和操作
	}

	// reference:
	// 1. https://github.com/tuneinsight/lattigo/discussions/257
	// 2. https://eprint.iacr.org/2021/315.pdf

	/*
		ciphertextMax := bfv.NewCiphertext(params, 1)      // 保存加密后的最大值
		ciphertextMin := bfv.NewCiphertext(params, 1)      // 保存加密后的最小值
		ciphertextMaxIndex := bfv.NewCiphertext(params, 1) // 保存加密后的最大值的索引
		ciphertextMinIndex := bfv.NewCiphertext(params, 1) // 保存加密后的最小值的索引

		// 待实现的两个求值操作：求最大值和最小值，找出最大的那个值以及对应的索引位置
		// 如果输入中有相同的值怎么办？ 希望输出排在前面的那个值，即排在前面的优先级更高
		evaluator.Max(ciphertexts, ciphertextMax, ciphertextMaxIndex)
		evaluator.Min(ciphertexts, ciphertextMin, ciphertextMinIndex)
	*/

	// 求和结果解密示例
	plaintext := bfv.NewPlaintext(params)
	decryptor.Decrypt(ciphertext, plaintext)
	res := encoder.DecodeUintNew(plaintext)
	fmt.Printf("%+v \n", res[0]) // 总和: 14787
}
