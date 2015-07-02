/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef CRYP_TAF_H
#define CRYP_TAF_H

#include <tee_api.h>

TEE_Result ta_entry_allocate_operation(uint32_t param_type, TEE_Param params[4]
);

TEE_Result ta_entry_free_operation(uint32_t param_type, TEE_Param params[4]
);

TEE_Result ta_entry_get_operation_info(uint32_t param_type, TEE_Param params[4]
);

TEE_Result ta_entry_reset_operation(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_set_operation_key(uint32_t param_type, TEE_Param params[4]
);

TEE_Result ta_entry_set_operation_key2(uint32_t param_type, TEE_Param params[4]
);

TEE_Result ta_entry_copy_operation(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_digest_update(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_digest_do_final(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_cipher_init(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_cipher_update(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_cipher_do_final(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_mac_init(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_mac_update(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_mac_final_compute(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_mac_final_compare(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_allocate_transient_object(uint32_t param_type,
					      TEE_Param params[4]);

TEE_Result ta_entry_free_transient_object(uint32_t param_type,
					  TEE_Param params[4]);

TEE_Result ta_entry_reset_transient_object(uint32_t param_type,
					   TEE_Param params[4]);

TEE_Result ta_entry_populate_transient_object(uint32_t param_type,
					      TEE_Param params[4]);

TEE_Result ta_entry_copy_object_attributes(uint32_t param_type,
					   TEE_Param params[4]);

TEE_Result ta_entry_generate_key(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_asymmetric_encrypt(uint32_t param_type,
				       TEE_Param params[4]);

TEE_Result ta_entry_asymmetric_decrypt(uint32_t param_type,
				       TEE_Param params[4]);

TEE_Result ta_entry_asymmetric_sign_digest(uint32_t param_type,
					   TEE_Param params[4]);

TEE_Result ta_entry_asymmetric_verify_digest(uint32_t param_type,
					     TEE_Param params[4]);

TEE_Result ta_entry_derive_key(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_random_number_generate(uint32_t param_type,
					   TEE_Param params[4]);

TEE_Result ta_entry_ae_init(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_ae_update_aad(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_ae_update(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_ae_encrypt_final(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_ae_decrypt_final(uint32_t param_type, TEE_Param params[4]);

TEE_Result ta_entry_get_object_buffer_attribute(uint32_t param_type,
						TEE_Param params[4]);

TEE_Result ta_entry_get_object_value_attribute(uint32_t param_type,
					       TEE_Param params[4]);

#endif /*CRYP_TAF_H */
