from main import hex_hash


def run_tests():
    tests_passed = 0
    tests_not_passed = 0
    test_index = 0
    with open('tests_texts.txt') as texts, open('tests_answers.txt') as answers:
        msg = texts.readline()
        while msg:
            msg_utf_encoded = msg.encode('utf-8')
            chunk_size = 256
            result = hex_hash(msg_utf_encoded, chunk_size)
            answer = answers.readline()
            if result == answer[:-1]:
                tests_passed += 1
            else:
                tests_not_passed += 1
                print('Test not passed index ' + str(test_index))
            msg = texts.readline()
            test_index += 1
    print('Tests passed: ' + str(tests_passed))
    print('Tests not passed: ' + str(tests_not_passed))


if __name__ == '__main__':
    run_tests()

