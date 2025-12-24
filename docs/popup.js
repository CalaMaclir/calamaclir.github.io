// ── 定数定義 ──
const EC_ALGORITHM = "ECDH";
const DEFAULT_EC_CURVE = "P-521";
const AES_ALGORITHM = "AES-GCM";
const AES_KEY_LENGTH = 256;
const AES_IV_LENGTH = 12;
const PUBKEY_SHARE_BASE_URL = "https://calamaclir.github.io/index.html";
const HEADER_CHECK_SIZE = 1024 * 1024;
const MAGIC_REQ_PARAM = "magic_req";
const MAGIC_SENDER_PARAM = "sender";

// ── QRコード用定数 ──
const QR_CODE_CORRECT_LEVEL = QRCode.CorrectLevel.L;
const QR_CODE_SIZE = 256;

// ── i18n リソース (UI表示用) ──
const resources = {
  ja: {
    app_desc: "公開鍵暗号化を利用したファイルの暗号化・復号Chrome拡張機能<br>鍵の管理と暗号化、復号の処理が手軽にできます<br>鍵はブラウザ内の IndexedDB に保存され、すべての処理はローカルで実施されます",
    link_manual: "簡単な説明はこちらをごらんください",
    processing: "処理中...",
    target_files_header: "暗号化／復号の対象ファイル",
    drop_area_text: "ここにファイルをドロップ",
    encrypt_title: "暗号化",
    encrypt_instruction: "暗号化で使用する公開鍵のファイルを読み込んでください",
    pubkey_select_header: "公開鍵選択 (.pubkey XML)",
    encrypt_btn: "暗号化",
    decrypt_title: "復号",
    decrypt_instruction: "秘密鍵は鍵一覧から自動選択されます",
    decrypt_btn: "復号",
    privkey_import_header: "秘密鍵インポート (.pvtkey XML)",
    key_mgmt_header: "鍵管理",
    key_name_label: "鍵名 (英数字、_, -, @, . のみ): ",
    key_name_placeholder: "例: MyKey01",
    algo_ec: "楕円曲線 (ECDH)",
    generate_btn: "鍵生成",
    key_list_header: "鍵一覧",
    col_keyname: "鍵名",
    col_type: "種別",
    col_info: "鍵情報",
    col_operation: "操作",
    warning_header: "取り扱い注意！",
    warning_text: "以下の操作は、<strong>すべての鍵情報を削除</strong>します。<br>この操作は元に戻せませんので、十分に注意してください。",
    reset_db_btn: "鍵一覧初期化",
    reset_ui_btn: "画面を初期化する",
    reload_url_btn: "URL公開鍵を読み直す",
    // JS内メッセージ
    fingerprint: "フィンガープリント",
    copy: "Copy",
    copied: "コピーしました",
    export_pub: "公開鍵をエクスポート",
    share_url: "公開鍵をURL/QRコードで共有",
    export_priv: "秘密鍵をエクスポート",
    delete: "削除",
    checking: "確認中...",
    ok_decryptable: "復号可能",
    ng_nokey: "復号不可 (鍵が見つかりません)",
    unknown_format: "形式不明",
    confirm_priv_export: "【注意】秘密鍵のエクスポートは非常に危険です。秘密鍵が漏洩すると、他の人によって暗号化されたデータが復号される可能性があります\n\n本当に秘密鍵をエクスポートしてもよろしいですか？",
    confirm_delete: "鍵 {name} を削除してよろしいですか？",
    confirm_reset_db: "本当に全ての鍵一覧を削除しますか？ この操作は元に戻せません。",
    alert_deleted: "鍵 {name} を削除しました",
    alert_reset_done: "鍵一覧が初期化されました。",
    alert_reset_err: "鍵一覧の初期化中にエラーが発生しました。",
    alert_blocked: "他のタブで開いている可能性があります。",
    alert_no_file_enc: "暗号化するファイルがありません。",
    alert_no_file_dec: "復号するファイルがありません。",
    alert_done_result: "処理が完了しました。\n成功: {success}件\n失敗: {fail}件",
    msg_enc_start: "暗号化処理を開始します...",
    msg_enc_processing: "暗号化中: {name}",
    msg_dec_start: "復号処理を開始します...",
    msg_dec_processing: "復号中: {name}",
    
    // アラート用プレフィックス
    alert_ec_gen_done: "楕円曲線鍵ペア生成完了: {name}",
    alert_ec_gen_err: "楕円曲線鍵生成エラー: ",
    alert_unsupported_alg: "選択されたアルゴリズムはサポートされていません。",
    alert_pub_not_found: "公開鍵が見つかりません",
    alert_import_pub_err: "公開鍵 {name} のインポートエラー: ",
    alert_priv_exists: "秘密鍵 {name} は既に存在するため、インポートをスキップします。",
    alert_import_priv_done: "秘密鍵インポート完了",
    alert_import_priv_err: "秘密鍵 {name} のインポートエラー: ",
    alert_keyname_invalid: "鍵名が不正です。英数字、_, -, @, . のみ使用可能です。",
    alert_keyname_exists: "同名の鍵が既に存在します",
    alert_url_pub_mismatch: "[warning!] 公開鍵とフィンガープリントが一致しません！\n共有されたフィンガープリント: {expected}\n公開鍵から算出されたフィンガープリント: {actual}",
    alert_url_pub_ok: "URLから公開鍵を受信しました\n公開鍵とフィンガープリントは一致します（公開鍵の改ざんはありません）\nフィンガープリント: {fp}",
    alert_url_load_err: "URL公開鍵の読み込みに失敗しました: ",
    
    label_pub_url: "{name} の 公開鍵URL",
    label_pub_url_desc: "公開鍵をURL/QRコードで共有できます",
    btn_copy_url: "公開鍵のURLをコピー",
    
    header_export_priv: "{name} の 秘密鍵をエクスポートする",
    header_export_pub: "{name} の 公開鍵をエクスポートする",
    warn_priv_sensitive: "※ 秘密鍵は非常にセンシティブな情報です。取り扱いには十分ご注意ください。",
    btn_download_pub: "公開鍵をダウンロードする",
    btn_download_priv: "秘密鍵（取り扱い注意！！）をダウンロードする",
    
    err_no_priv_exists: "秘密鍵が存在しません",
    err_no_pub_exists: "公開鍵が存在しません",
    err_export_fail: "エクスポートエラー: ",
    err_aes_dec_fail: "AES復号に失敗しました: ",
    
    status_unknown: "データ不足",
    status_unencrypted: "非暗号化/不明な形式",
    status_unknown_type: "不明なエントリータイプ",
    status_parse_err: "解析エラー",

    // マジックリンク用
    magic_link_header: "マジックリンク (簡単鍵交換)",
    magic_link_desc: "相手にこのURLを送るだけで、相手の公開鍵を簡単に受け取ることができます。",
    btn_create_magic_link: "鍵交換リクエストURLを作成",
    magic_req_prompt: "あなたの名前（相手に表示されます）を入力してください:",
    wizard_title: "{sender} さんからの安全な通信リクエスト",
    wizard_desc: "{sender} さんが、あなたと安全にファイルをやり取りするための準備を求めています。<br>下のボタンを押して、準備を開始してください。",
    wizard_btn_start: "準備を開始する (鍵生成)",
    wizard_step_done: "準備完了！",
    wizard_reply_inst: "以下のURLをコピーして、{sender} さんに返信してください。",
    btn_copy_reply_url: "返信URLをコピー"
  },
  en: {
    app_desc: "File encryption/decryption Chrome extension using public key cryptography.<br>Manage keys and encrypt/decrypt files easily.<br>Keys are stored in IndexedDB within the browser, and all processing is done locally.",
    link_manual: "Click here for a brief explanation (Japanese)",
    processing: "Processing...",
    target_files_header: "Files to Encrypt/Decrypt",
    drop_area_text: "Drop files here",
    encrypt_title: "Encryption",
    encrypt_instruction: "Load public key file(s) for encryption",
    pubkey_select_header: "Select Public Key (.pubkey XML)",
    encrypt_btn: "Encrypt",
    decrypt_title: "Decryption",
    decrypt_instruction: "Private key is automatically selected from the list",
    decrypt_btn: "Decrypt",
    privkey_import_header: "Import Private Key (.pvtkey XML)",
    key_mgmt_header: "Key Management",
    key_name_label: "Key Name (Alphanumeric, _, -, @, . only): ",
    key_name_placeholder: "e.g. MyKey01",
    algo_ec: "Elliptic Curve (ECDH)",
    generate_btn: "Generate Key",
    key_list_header: "Key List",
    col_keyname: "Name",
    col_type: "Type",
    col_info: "Info",
    col_operation: "Actions",
    warning_header: "Warning!",
    warning_text: "The following operation will <strong>delete all key information</strong>.<br>This cannot be undone, so please be careful.",
    reset_db_btn: "Initialize Key List",
    reset_ui_btn: "Reset Screen",
    reload_url_btn: "Reload Public Key from URL",
    // JS Messages
    fingerprint: "Fingerprint",
    copy: "Copy",
    copied: "Copied",
    export_pub: "Export Public Key",
    share_url: "Share via URL/QR",
    export_priv: "Export Private Key",
    delete: "Delete",
    checking: "Checking...",
    ok_decryptable: "Decryptable",
    ng_nokey: "Not Decryptable (No Key)",
    unknown_format: "Unknown Format",
    confirm_priv_export: "[WARNING] Exporting a private key is very dangerous. If the private key is leaked, data encrypted by others can be decrypted.\n\nAre you sure you want to export the private key?",
    confirm_delete: "Are you sure you want to delete key {name}?",
    confirm_reset_db: "Are you sure you want to delete all keys? This cannot be undone.",
    alert_deleted: "Deleted key {name}",
    alert_reset_done: "Key list has been initialized.",
    alert_reset_err: "Error occurred while initializing key list.",
    alert_blocked: "Database may be open in another tab.",
    alert_no_file_enc: "No files to encrypt.",
    alert_no_file_dec: "No files to decrypt.",
    alert_done_result: "Process completed.\nSuccess: {success}\nFailed: {fail}",
    msg_enc_start: "Starting encryption...",
    msg_enc_processing: "Encrypting: {name}",
    msg_dec_start: "Starting decryption...",
    msg_dec_processing: "Decrypting: {name}",
    
    alert_ec_gen_done: "EC Key Pair generated: {name}",
    alert_ec_gen_err: "EC Key Generation Error: ",
    alert_unsupported_alg: "Selected algorithm is not supported.",
    alert_pub_not_found: "Public key not found",
    alert_import_pub_err: "Import error for public key {name}: ",
    alert_priv_exists: "Private key {name} already exists. Skipping.",
    alert_import_priv_done: "Private key import completed",
    alert_import_priv_err: "Import error for private key {name}: ",
    alert_keyname_invalid: "Invalid key name. Only Alphanumeric, _, -, @, . allowed.",
    alert_keyname_exists: "Key with the same name already exists",
    alert_url_pub_mismatch: "[warning!] Public key and fingerprint do not match!\nShared FP: {expected}\nCalculated FP: {actual}",
    alert_url_pub_ok: "Received public key from URL.\nPublic key and fingerprint match (No tampering detected).\nFingerprint: {fp}",
    alert_url_load_err: "Failed to load public key from URL: ",
    
    label_pub_url: "Public Key URL for {name}",
    label_pub_url_desc: "You can share the public key via URL or QR Code",
    btn_copy_url: "Copy URL",
    
    header_export_priv: "Export Private Key for {name}",
    header_export_pub: "Export Public Key for {name}",
    warn_priv_sensitive: "※ Private keys are extremely sensitive. Handle with care.",
    btn_download_pub: "Download Public Key",
    btn_download_priv: "Download Private Key (HANDLE WITH CARE!!)",
    
    err_no_priv_exists: "Private key does not exist",
    err_no_pub_exists: "Public key does not exist",
    err_export_fail: "Export error: ",
    err_aes_dec_fail: "AES decryption failed: ",
    
    status_unknown: "Insufficient Data",
    status_unencrypted: "Unencrypted/Unknown",
    status_unknown_type: "Unknown Entry",
    status_parse_err: "Parse Error",

    // Magic Link
    magic_link_header: "Magic Link (Easy Key Exchange)",
    magic_link_desc: "Send this URL to someone to easily receive their public key.",
    btn_create_magic_link: "Create Request URL",
    magic_req_prompt: "Enter your name (shown to the recipient):",
    wizard_title: "Secure Communication Request from {sender}",
    wizard_desc: "{sender} wants to set up secure file exchange with you.<br>Click the button below to start.",
    wizard_btn_start: "Start Setup (Generate Key)",
    wizard_step_done: "Ready!",
    wizard_reply_inst: "Copy the URL below and send it back to {sender}.",
    btn_copy_reply_url: "Copy Reply URL"
  },
  fr: {
    app_desc: "Extension Chrome de chiffrement et déchiffrement de fichiers utilisant la cryptographie à clé publique.<br>Gérez vos clés et chiffrez/déchiffrez des fichiers facilement.<br>Les clés sont stockées dans IndexedDB dans votre navigateur, et tout le traitement est effectué localement.",
    link_manual: "Cliquez ici pour une brève explication (japonais)",
    processing: "Traitement en cours...",
    target_files_header: "Fichiers à chiffrer/déchiffrer",
    drop_area_text: "Déposez les fichiers ici",
    encrypt_title: "Chiffrement",
    encrypt_instruction: "Chargez le(s) fichier(s) de clé publique pour le chiffrement",
    pubkey_select_header: "Sélectionner la clé publique (XML .pubkey)",
    encrypt_btn: "Chiffrer",
    decrypt_title: "Déchiffrement",
    decrypt_instruction: "La clé privée est sélectionnée automatiquement dans la liste",
    decrypt_btn: "Déchiffrer",
    privkey_import_header: "Importer une clé privée (XML .pvtkey)",
    key_mgmt_header: "Gestion des clés",
    key_name_label: "Nom de la clé (Alphanumérique, _, -, @, . uniquement) : ",
    key_name_placeholder: "ex: MaCle01",
    algo_ec: "Courbe Elliptique (ECDH)",
    generate_btn: "Générer une clé",
    key_list_header: "Liste des clés",
    col_keyname: "Nom",
    col_type: "Type",
    col_info: "Info",
    col_operation: "Actions",
    warning_header: "Attention !",
    warning_text: "L'opération suivante va <strong>supprimer toutes les informations de clé</strong>.<br>Cette action est irréversible, veuillez donc faire attention.",
    reset_db_btn: "Initialiser la liste des clés",
    reset_ui_btn: "Réinitialiser l'écran",
    reload_url_btn: "Recharger la clé publique depuis l'URL",
    // JS Messages
    fingerprint: "Empreinte",
    copy: "Copier",
    copied: "Copié",
    export_pub: "Exporter la clé publique",
    share_url: "Partager via URL/QR",
    export_priv: "Exporter la clé privée",
    delete: "Supprimer",
    checking: "Vérification...",
    ok_decryptable: "Déchiffrable",
    ng_nokey: "Non déchiffrable (Pas de clé)",
    unknown_format: "Format inconnu",
    confirm_priv_export: "[ATTENTION] L'exportation d'une clé privée est très dangereuse. Si la clé privée fuite, les données chiffrées par d'autres peuvent être déchiffrées.\n\nÊtes-vous sûr de vouloir exporter la clé privée ?",
    confirm_delete: "Êtes-vous sûr de vouloir supprimer la clé {name} ?",
    confirm_reset_db: "Êtes-vous sûr de vouloir supprimer toutes les clés ? Cette action est irréversible.",
    alert_deleted: "Clé {name} supprimée",
    alert_reset_done: "La liste des clés a été initialisée.",
    alert_reset_err: "Une erreur s'est produite lors de l'initialisation de la liste des clés.",
    alert_blocked: "La base de données peut être ouverte dans un autre onglet.",
    alert_no_file_enc: "Aucun fichier à chiffrer.",
    alert_no_file_dec: "Aucun fichier à déchiffrer.",
    alert_done_result: "Traitement terminé.\nSuccès : {success}\nÉchec : {fail}",
    msg_enc_start: "Démarrage du chiffrement...",
    msg_enc_processing: "Chiffrement : {name}",
    msg_dec_start: "Démarrage du déchiffrement...",
    msg_dec_processing: "Déchiffrement : {name}",
    
    alert_ec_gen_done: "Paire de clés EC générée : {name}",
    alert_ec_gen_err: "Erreur de génération de clé EC : ",
    alert_unsupported_alg: "L'algorithme sélectionné n'est pas supporté.",
    alert_pub_not_found: "Clé publique introuvable",
    alert_import_pub_err: "Erreur d'importation pour la clé publique {name} : ",
    alert_priv_exists: "La clé privée {name} existe déjà. Ignoré.",
    alert_import_priv_done: "Importation de la clé privée terminée",
    alert_import_priv_err: "Erreur d'importation pour la clé privée {name} : ",
    alert_keyname_invalid: "Nom de clé invalide. Seuls Alphanumérique, _, -, @, . sont autorisés.",
    alert_keyname_exists: "Une clé portant le même nom existe déjà",
    alert_url_pub_mismatch: "[Attention !] La clé publique et l'empreinte ne correspondent pas !\nEmpreinte partagée : {expected}\nEmpreinte calculée : {actual}",
    alert_url_pub_ok: "Clé publique reçue depuis l'URL.\nLa clé publique et l'empreinte correspondent (Aucune falsification détectée).\nEmpreinte : {fp}",
    alert_url_load_err: "Échec du chargement de la clé publique depuis l'URL : ",
    
    label_pub_url: "URL de la clé publique pour {name}",
    label_pub_url_desc: "Vous pouvez partager la clé publique via URL ou QR Code",
    btn_copy_url: "Copier l'URL",
    
    header_export_priv: "Exporter la clé privée pour {name}",
    header_export_pub: "Exporter la clé publique pour {name}",
    warn_priv_sensitive: "※ Les clés privées sont extrêmement sensibles. Manipulez-les avec précaution.",
    btn_download_pub: "Télécharger la clé publique",
    btn_download_priv: "Télécharger la clé privée (MANIPULER AVEC PRÉCAUTION !!)",
    
    err_no_priv_exists: "La clé privée n'existe pas",
    err_no_pub_exists: "La clé publique n'existe pas",
    err_export_fail: "Erreur d'exportation : ",
    err_aes_dec_fail: "Échec du déchiffrement AES : ",
    
    status_unknown: "Données insuffisantes",
    status_unencrypted: "Non chiffré/Inconnu",
    status_unknown_type: "Entrée inconnue",
    status_parse_err: "Erreur d'analyse",

    // Magic Link
    magic_link_header: "Lien Magique (Échange de clés facile)",
    magic_link_desc: "Envoyez cette URL pour recevoir facilement la clé publique de quelqu'un.",
    btn_create_magic_link: "Créer une URL de demande",
    magic_req_prompt: "Entrez votre nom (affiché au destinataire) :",
    wizard_title: "Demande de communication sécurisée de {sender}",
    wizard_desc: "{sender} souhaite établir un échange de fichiers sécurisé avec vous.<br>Cliquez sur le bouton ci-dessous pour commencer.",
    wizard_btn_start: "Commencer (Générer une clé)",
    wizard_step_done: "Prêt !",
    wizard_reply_inst: "Copiez l'URL ci-dessous et renvoyez-la à {sender}.",
    btn_copy_reply_url: "Copier l'URL de réponse"
  },
  lb: {
    app_desc: "Chrome-Extensioun fir Verschlësselung an Entschlësselung vun Dateien mat ëffentleche Schlësselen.<br>Verwalten Är Schlësselen an verschlësselt/entschlësselt Dateien einfach.<br>D'Schlëssel ginn an der IndexedDB an Ärem Browser gespäichert, an all Veraarbechtung gëtt lokal gemaach.",
    link_manual: "Klickt hei fir eng kuerz Erklärung (Japanesch)",
    processing: "Veraarbechtung...",
    target_files_header: "Dateien fir ze Verschlësselen/Entschlësselen",
    drop_area_text: "Dateien hei ofleeën",
    encrypt_title: "Verschlësselung",
    encrypt_instruction: "Lued ëffentlech Schlësseldatei(en) fir Verschlësselung",
    pubkey_select_header: "Wielt ëffentleche Schlëssel (XML .pubkey)",
    encrypt_btn: "Verschlësselen",
    decrypt_title: "Entschlësselung",
    decrypt_instruction: "De private Schlëssel gëtt automatesch aus der Lëscht ausgewielt",
    decrypt_btn: "Entschlësselen",
    privkey_import_header: "Privaten Schlëssel importéieren (XML .pvtkey)",
    key_mgmt_header: "Schlësselverwaltung",
    key_name_label: "Schlësselnumm (Nëmmen Alphanumeresch, _, -, @, .) : ",
    key_name_placeholder: "z.B. MäiSchlëssel01",
    algo_ec: "Elliptesch Kéier (ECDH)",
    generate_btn: "Schlëssel generéieren",
    key_list_header: "Schlëssellëscht",
    col_keyname: "Numm",
    col_type: "Typ",
    col_info: "Info",
    col_operation: "Aktiounen",
    warning_header: "Opgepasst!",
    warning_text: "Déi folgend Operatioun wäert <strong>all Schlësselinformatioun läschen</strong>.<br>Dëst kann net réckgängeg gemaach ginn, also passt w.e.g. op.",
    reset_db_btn: "Schlëssellëscht initialiséieren",
    reset_ui_btn: "Bildschierm zrécksetzen",
    reload_url_btn: "Ëffentleche Schlëssel vun URL nei lueden",
    // JS Messages
    fingerprint: "Fangerofdrock",
    copy: "Kopéieren",
    copied: "Kopéiert",
    export_pub: "Ëffentleche Schlëssel exportéieren",
    share_url: "Deelen iwwer URL/QR",
    export_priv: "Privaten Schlëssel exportéieren",
    delete: "Läschen",
    checking: "Iwwerpréiwen...",
    ok_decryptable: "Entschlësselbar",
    ng_nokey: "Net entschlësselbar (Kee Schlëssel)",
    unknown_format: "Onbekannt Format",
    confirm_priv_export: "[OPGEPASST] En private Schlëssel exportéieren ass ganz geféierlech. Wann de private Schlëssel geleckt gëtt, kënnen Donnéeën, déi vun aneren verschlësselt goufen, entschlësselt ginn.\n\nSidd Dir sécher, datt Dir de private Schlëssel exportéiere wëllt?",
    confirm_delete: "Sidd Dir sécher, datt Dir de Schlëssel {name} läsche wëllt?",
    confirm_reset_db: "Sidd Dir sécher, datt Dir all Schlëssel läsche wëllt? Dëst kann net réckgängeg gemaach ginn.",
    alert_deleted: "Schlëssel {name} geläscht",
    alert_reset_done: "Schlëssellëscht gouf initialiséiert.",
    alert_reset_err: "Feeler beim Initialiséieren vun der Schlëssellëscht.",
    alert_blocked: "Datebank kéint an engem aneren Tab op sinn.",
    alert_no_file_enc: "Keng Dateien fir ze verschlësselen.",
    alert_no_file_dec: "Keng Dateien fir ze entschlësselen.",
    alert_done_result: "Veraarbechtung fäerdeg.\nErfolleg: {success}\nFeeler: {fail}",
    msg_enc_start: "Verschlësselung starten...",
    msg_enc_processing: "Verschlësselen: {name}",
    msg_dec_start: "Entschlësselung starten...",
    msg_dec_processing: "Entschlësselen: {name}",
    
    alert_ec_gen_done: "EC Schlësselpaar generéiert: {name}",
    alert_ec_gen_err: "EC Schlëssel Generatiounsfeeler: ",
    alert_unsupported_alg: "Ausgewielten Algorithmus gëtt net ënnerstëtzt.",
    alert_pub_not_found: "Ëffentleche Schlëssel net fonnt",
    alert_import_pub_err: "Importfeeler fir ëffentleche Schlëssel {name}: ",
    alert_priv_exists: "Private Schlëssel {name} existéiert schonn. Iwwersprongen.",
    alert_import_priv_done: "Privaten Schlëssel Import fäerdeg",
    alert_import_priv_err: "Importfeeler fir private Schlëssel {name}: ",
    alert_keyname_invalid: "Ongültege Schlësselnumm. Nëmmen Alphanumeresch, _, -, @, . erlaabt.",
    alert_keyname_exists: "Schlëssel mam selwechten Numm existéiert schonn",
    alert_url_pub_mismatch: "[Opgepasst!] Ëffentleche Schlëssel a Fangerofdrock stëmmen net iwwerenee!\nGedeelten FP: {expected}\nBerechent FP: {actual}",
    alert_url_pub_ok: "Ëffentleche Schlëssel vun URL kritt.\nËffentleche Schlëssel a Fangerofdrock stëmmen iwwereneen (Keng Manipulatioun festgestallt).\nFangerofdrock: {fp}",
    alert_url_load_err: "Feeler beim Lueden vum ëffentleche Schlëssel vun der URL: ",
    
    label_pub_url: "Ëffentleche Schlëssel URL fir {name}",
    label_pub_url_desc: "Dir kënnt den ëffentleche Schlëssel iwwer URL oder QR Code deelen",
    btn_copy_url: "URL kopéieren",
    
    header_export_priv: "Privaten Schlëssel exportéieren fir {name}",
    header_export_pub: "Ëffentleche Schlëssel exportéieren fir {name}",
    warn_priv_sensitive: "※ Privat Schlëssel sinn extrem sensibel. Gitt virsiichteg domat ëm.",
    btn_download_pub: "Ëffentleche Schlëssel eroflueden",
    btn_download_priv: "Privaten Schlëssel eroflueden (OPGEPASST!!)",
    
    err_no_priv_exists: "Privaten Schlëssel existéiert net",
    err_no_pub_exists: "Ëffentleche Schlëssel existéiert net",
    err_export_fail: "Exportfeeler: ",
    err_aes_dec_fail: "AES Entschlësselung feelgeschloen: ",
    
    status_unknown: "Net genuch Daten",
    status_unencrypted: "Net verschlësselt/Onbekannt",
    status_unknown_type: "Onbekannten Entrée",
    status_parse_err: "Analysfeeler",

    // Magic Link
    magic_link_header: "Magic Link (Einfach Schlësselaustausch)",
    magic_link_desc: "Schéckt dës URL un een fir einfach hiren ëffentleche Schlëssel ze kréien.",
    btn_create_magic_link: "Ufro-URL erstellen",
    magic_req_prompt: "Gitt Ären Numm an (gëtt dem Empfänger gewisen):",
    wizard_title: "Sécher Kommunikatiounsufro vun {sender}",
    wizard_desc: "{sender} wëll e sécheren Dateiaustausch mat Iech opbauen.<br>Klickt op de Knäppchen hei ënnen fir unzefänken.",
    wizard_btn_start: "Ufänken (Schlëssel generéieren)",
    wizard_step_done: "Pret!",
    wizard_reply_inst: "Kopéiert d'URL hei ënnen a schéckt se zréck un {sender}.",
    btn_copy_reply_url: "Äntwert URL kopéieren"
  }
};

// ── グローバル変数 ──
let db;
const keyStore = {};
const importedPrivateKeys = [];
const encryptionPublicKeys = [];
const filesToProcess = [];
let currentLang = 'ja'; // デフォルト

const HIDEABLE_UI_BLOCK_IDS = [
  'pubkey-file-select-block',
  'decrypt-block',
  'privKeyImport',
  'keyManagement',
  'exportArea',
  'resetSection',
  'decrypt-block',
  'magicLinkSection'
];

// ── i18n ヘルパー ──
function t(key, params = {}) {
  let text = resources[currentLang][key] || key;
  for (const [k, v] of Object.entries(params)) {
    text = text.replace(`{${k}}`, v);
  }
  return text;
}

function updateUIText() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    el.innerHTML = t(key); // HTMLタグを含む場合があるためinnerHTML
  });
  // プレースホルダー更新
  const keyNameInput = document.getElementById('keyNameInput');
  if(keyNameInput) keyNameInput.placeholder = t('key_name_placeholder');

  // 言語スイッチャーの表示更新
  document.getElementById('lang-ja').className = currentLang === 'ja' ? 'active' : '';
  document.getElementById('lang-en').className = currentLang === 'en' ? 'active' : '';
  document.getElementById('lang-fr').className = currentLang === 'fr' ? 'active' : '';
  document.getElementById('lang-lb').className = currentLang === 'lb' ? 'active' : '';
  
  // リスト再描画
  refreshKeyList(); 
}

function changeLanguage(lang) {
  currentLang = lang;
  updateUIText();
}

// ── Fingerprint生成関数 ──
async function calcFingerprint(publicKey) {
  const raw = await crypto.subtle.exportKey("raw", publicKey);
  const hash = await crypto.subtle.digest("SHA-256", raw);
  let b64 = btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return b64;
}

// ── UI補助関数 ──
function showSpinner(text) {
  const spinner = document.getElementById('spinner');
  spinner.textContent = text || t('processing');
  spinner.style.display = 'block';
}
function updateSpinnerText(text) {
    document.getElementById('spinner').textContent = text;
}
function hideSpinner() {
  document.getElementById('spinner').style.display = 'none';
}
function clearExportArea() {
  const exportArea = document.getElementById('exportArea');
  exportArea.textContent = "";
  exportArea.style.display = 'none';
}
function dispExportArea() {
  document.getElementById('exportArea').style.display = '';
}

function hideResetUiButtonsInExtension() {
  if (typeof chrome !== "undefined" && typeof chrome.runtime !== "undefined") {
    const UIinitArea = document.getElementById('UI-init');
    if (UIinitArea) UIinitArea.style.display = "none";
  }
}

// --- UI初期化時 ---
function resetUI() {
  filesToProcess.length = 0;
  encryptionPublicKeys.length = 0;
  document.getElementById('fileList').textContent = "";
  document.getElementById('fileDropArea').textContent = t('drop_area_text');
  document.getElementById('pubKeyList').textContent = "";
  document.getElementById('fileSelect').value = "";
  document.getElementById('privKeyList').textContent = "";
  hideSpinner();
  clearExportArea();
  setBlocksDisplay(HIDEABLE_UI_BLOCK_IDS, "");
}

function resetUIEncrypt() {
  filesToProcess.length = 0;
  document.getElementById('fileList').textContent = "";
  document.getElementById('fileDropArea').textContent = t('drop_area_text');
  document.getElementById('fileSelect').value = "";
  hideSpinner();
}

// ── ユーティリティ関数 ──
function concatUint8Arrays(arrays) {
  let total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  let result = new Uint8Array(total);
  let offset = 0;
  arrays.forEach(arr => { result.set(arr, offset); offset += arr.length; });
  return result;
}
function writeInt32LE(val) {
  const buf = new ArrayBuffer(4);
  new DataView(buf).setInt32(0, val, true);
  return new Uint8Array(buf);
}
function readInt32LE(view, offset) {
  return view.getInt32(offset, true);
}
function base64ToBase64Url(b64) {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64UrlToBase64(url) {
  let b64 = url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) { b64 += '='; }
  return b64;
}
function arrayBufferToBase64(buffer) {
  let binary = '';
  let bytes = (buffer instanceof Uint8Array) ? buffer : new Uint8Array(buffer);
  for (let b of bytes) { binary += String.fromCharCode(b); }
  return btoa(binary);
}
function base64ToUint8Array(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
  return bytes;
}

// ── IndexedDB 関連 ──
function initDB() {
  const request = indexedDB.open("PubliCryptDB", 2);
  request.onupgradeneeded = function(e) {
    db = e.target.result;
    if (!db.objectStoreNames.contains("keys")) {
      db.createObjectStore("keys", { keyPath: "name" });
    }
  };
  request.onsuccess = function(e) {
    db = e.target.result;
    loadKeysFromDB();
  };
  request.onerror = function(e) {
    console.error("IndexedDB error", e);
  };
}
function storeKeyRecord(record) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("keys", "readwrite");
    const store = transaction.objectStore("keys");
    const req = store.put(record);
    req.onsuccess = () => resolve();
    req.onerror = (e) => reject(e);
  });
}
function deleteKeyRecord(name) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("keys", "readwrite");
    const store = transaction.objectStore("keys");
    const req = store.delete(name);
    req.onsuccess = () => resolve();
    req.onerror = (e) => reject(e);
  });
}
function getKeyRecord(name) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("keys", "readonly");
    const store = transaction.objectStore("keys");
    const req = store.get(name);
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e);
  });
}
async function storeKeyPair(name, type, publicJwk, privateJwk) {
  let record = await getKeyRecord(name);
  if (!record) {
    record = { name: name, type: type, publicKeyJwk: publicJwk, privateKeyJwk: privateJwk };
  } else {
    record.type = type;
    record.publicKeyJwk = publicJwk;
    record.privateKeyJwk = privateJwk;
  }
  await storeKeyRecord(record);
}
async function loadKeysFromDB() {
  const transaction = db.transaction("keys", "readonly");
  const store = transaction.objectStore("keys");
  const req = store.getAll();
  req.onsuccess = async function() {
    const records = req.result;
    for (const record of records) {
      if (record.publicKeyJwk && record.type === "EC") {
        const pubKey = await crypto.subtle.importKey(
          "jwk", record.publicKeyJwk,
          { name: EC_ALGORITHM, namedCurve: record.publicKeyJwk.crv },
          true, []
        );
        if (!keyStore[record.name]) { keyStore[record.name] = {}; }
        keyStore[record.name].publicKey = pubKey;
        keyStore[record.name].type = "EC";
        keyStore[record.name].curve = record.publicKeyJwk.crv;
        keyStore[record.name].fingerprint = await calcFingerprint(pubKey);
      }
      if (record.privateKeyJwk && record.type === "EC") {
        const privKey = await crypto.subtle.importKey(
          "jwk", record.privateKeyJwk,
          { name: EC_ALGORITHM, namedCurve: record.publicKeyJwk.crv },
          true, ["deriveKey"]
        );
        const raw = await crypto.subtle.exportKey("raw", keyStore[record.name].publicKey);
        const identifier = arrayBufferToBase64(raw);
        importedPrivateKeys.push({ name: record.name, identifier: identifier, cryptoKey: privKey, type: "EC" });
        if (!keyStore[record.name]) { keyStore[record.name] = {}; }
        keyStore[record.name].privateKey = privKey;
      }
    }
    refreshKeyList();
  }
}

// ── XML形式の鍵インポート（統合版） ──
function getXmlTagContent(xmlDoc, tagName) {
  const el = xmlDoc.getElementsByTagName(tagName)[0];
  return el ? el.textContent.trim() : null;
}
async function importPublicKeyFromXmlEC(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const x = getXmlTagContent(xmlDoc, "X");
  const y = getXmlTagContent(xmlDoc, "Y");
  const curve = getXmlTagContent(xmlDoc, "Curve") || DEFAULT_EC_CURVE;
  if (!x || !y) {
    throw new Error("X or Y not found in Public Key XML");
  }
  const jwk = { kty: "EC", crv: curve, x: x, y: y, ext: true };
  const cryptoKey = await crypto.subtle.importKey(
    "jwk", jwk,
    { name: EC_ALGORITHM, namedCurve: curve },
    true, []
  );
  const raw = await crypto.subtle.exportKey("raw", cryptoKey);
  const identifier = arrayBufferToBase64(raw);
  const fingerprint = await calcFingerprint(cryptoKey);
  return { name: fileName, identifier: identifier, cryptoKey: cryptoKey, type: "EC", curve: curve, fingerprint: fingerprint };
}
async function importPrivateKeyFromXmlEC(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const x = getXmlTagContent(xmlDoc, "X");
  const y = getXmlTagContent(xmlDoc, "Y");
  const d = getXmlTagContent(xmlDoc, "D");
  const curve = getXmlTagContent(xmlDoc, "Curve") || DEFAULT_EC_CURVE;
  if (!x || !y || !d) {
    throw new Error("Required elements not found in Private Key XML");
  }
  const jwkPrivate = { kty: "EC", crv: curve, x: x, y: y, d: d, ext: true };
  const privateCryptoKey = await crypto.subtle.importKey(
    "jwk", jwkPrivate,
    { name: EC_ALGORITHM, namedCurve: curve },
    true, ["deriveKey"]
  );
  const publicJwk = { kty: "EC", crv: curve, x: x, y: y, ext: true };
  const publicCryptoKey = await crypto.subtle.importKey(
    "jwk", publicJwk,
    { name: EC_ALGORITHM, namedCurve: curve },
    true, []
  );
  const raw = await crypto.subtle.exportKey("raw", publicCryptoKey);
  const identifier = arrayBufferToBase64(raw);
  const fingerprint = await calcFingerprint(publicCryptoKey);
  return { name: fileName, identifier: identifier, publicKey: publicCryptoKey, privateKey: privateCryptoKey, type: "EC", curve: curve, fingerprint: fingerprint };
}
async function importPublicKeyFromXmlUnified(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const rootTag = xmlDoc.documentElement.tagName;
  if (rootTag === "ECKeyValue") {
    return await importPublicKeyFromXmlEC(xmlString, fileName);
  } else {
    throw new Error("Unknown Public Key XML format");
  }
}
async function importPrivateKeyFromXmlUnified(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const rootTag = xmlDoc.documentElement.tagName;
  if (rootTag === "ECKeyValue") {
    return await importPrivateKeyFromXmlEC(xmlString, fileName);
  } else {
    throw new Error("Unknown Private Key XML format");
  }
}

// ── ファイルの復号可能性チェック機能 ──
async function checkFileDecryptability(file) {
  try {
    const slice = file.slice(0, HEADER_CHECK_SIZE); 
    const buffer = await slice.arrayBuffer();
    const view = new DataView(buffer);
    const uint8 = new Uint8Array(buffer);
    
    let offset = 0;
    
    if (buffer.byteLength < 4) return { status: 'UNKNOWN', message: t('status_unknown') };
    const entryCount = readInt32LE(view, offset);
    offset += 4;

    if (entryCount < 0 || entryCount > 1000) {
      return { status: 'UNKNOWN', message: t('status_unencrypted') };
    }

    for (let i = 0; i < entryCount; i++) {
      if (offset >= buffer.byteLength) break;
      
      const type = uint8[offset];
      offset += 1;
      
      if (type === 1) { // EC Entry
        if (offset + 4 > buffer.byteLength) break;
        const idLen = readInt32LE(view, offset);
        offset += 4;
        
        if (offset + idLen > buffer.byteLength) break;
        const recipientId = uint8.slice(offset, offset + idLen);
        const recipientIdB64 = arrayBufferToBase64(recipientId);
        offset += idLen;

        const matchedKey = importedPrivateKeys.find(k => k.identifier === recipientIdB64);
        if (matchedKey) {
          return { status: 'OK', keyName: matchedKey.name };
        }

        if (offset + 4 > buffer.byteLength) break;
        const ephLen = readInt32LE(view, offset);
        offset += 4 + ephLen;

        if (offset + 4 > buffer.byteLength) break;
        const wrapLen = readInt32LE(view, offset);
        offset += 4 + wrapLen;
      } else {
        return { status: 'UNKNOWN', message: t('status_unknown_type') };
      }
    }
    
    return { status: 'NO_KEY' };
    
  } catch (e) {
    console.error(e);
    return { status: 'UNKNOWN', message: t('status_parse_err') };
  }
}

// ── ファイルドラッグ＆ドロップ／選択処理 ──
const fileDropArea = document.getElementById('fileDropArea');
const fileListElem = document.getElementById('fileList');

async function addFilesToList(files) {
  for (let file of files) {
    filesToProcess.push(file);
    const li = document.createElement('li');
    
    const nameSpan = document.createElement('span');
    nameSpan.textContent = file.name;
    nameSpan.style.fontWeight = 'bold';
    li.appendChild(nameSpan);

    const statusSpan = document.createElement('span');
    statusSpan.style.marginLeft = '10px';
    statusSpan.style.fontSize = '0.9em';
    statusSpan.style.color = '#777';
    statusSpan.textContent = ' ⏳ ' + t('checking');
    li.appendChild(statusSpan);

    fileListElem.appendChild(li);

    checkFileDecryptability(file).then(result => {
      statusSpan.textContent = ""; 
      
      if (result.status === 'OK') {
        statusSpan.style.color = '#2e7d32'; 
        statusSpan.textContent = ` ✅ ${t('ok_decryptable')} (${t('col_keyname')}: ${result.keyName})`;
      } else if (result.status === 'NO_KEY') {
        statusSpan.style.color = '#c62828'; 
        statusSpan.textContent = ` ❌ ${t('ng_nokey')}`;
      } else {
        statusSpan.style.color = '#999';
        if (file.name.endsWith('.crypted')) {
            statusSpan.textContent = ` ⚠️ ${t('unknown_format')}`;
        }
      }
    });
  }
}

fileDropArea.addEventListener('dragover', (e) => {
  e.preventDefault();
  fileDropArea.style.borderColor = "#000";
});
fileDropArea.addEventListener('dragleave', (e) => {
  e.preventDefault();
  fileDropArea.style.borderColor = "#888";
});
fileDropArea.addEventListener('drop', (e) => {
  e.preventDefault();
  fileDropArea.style.borderColor = "#888";
  const files = e.dataTransfer.files;
  addFilesToList(files);
});
document.getElementById('fileSelect').addEventListener('change', (e) => {
  const files = e.target.files;
  addFilesToList(files);
  e.target.value = "";
});

// ── 公開鍵ファイル入力 ──
const pubKeyListElem = document.getElementById('pubKeyList');
document.getElementById('pubKeyInput').addEventListener('change', async (e) => {
  const files = e.target.files;
  for (let file of files) {
    const text = await file.text();
    try {
      const pubKey = await importPublicKeyFromXmlUnified(text, file.name);
      encryptionPublicKeys.push(pubKey);
      
      const li = document.createElement('li');
      const keyInfoDiv = document.createElement('div');
      keyInfoDiv.textContent = `${pubKey.name} (${pubKey.type})`;
      const br = document.createElement('br');
      const fpSpan = document.createElement('span');
      fpSpan.style.fontSize = '0.91em';
      fpSpan.style.color = '#777';
      fpSpan.textContent = `${t('fingerprint')}: ${pubKey.fingerprint}`;
      const copyBtn = document.createElement('button');
      copyBtn.textContent = t('copy');
      copyBtn.style.marginLeft = '6px';
      copyBtn.style.fontSize = '0.9em';
      copyBtn.style.padding = '2px 8px';
      copyBtn.onclick = () => {
          navigator.clipboard.writeText(pubKey.fingerprint);
          alert(t('copied'));
      };
      
      li.appendChild(keyInfoDiv);
      li.appendChild(br);
      li.appendChild(fpSpan);
      li.appendChild(copyBtn);
      
      pubKeyListElem.appendChild(li);
    } catch(err) {
      alert(t('alert_import_pub_err', {name: file.name}) + err.message);
    }
  }
  e.target.value = "";
});

// ── 秘密鍵ファイル入力 ──
const privKeyListElem = document.getElementById('privKeyList');
document.getElementById('privKeyInput').addEventListener('change', async (e) => {
  let imported = false;
  const files = e.target.files;
  for (let file of files) {
    const text = await file.text();
    try {
      let keyName = file.name;
      if (keyName.toLowerCase().endsWith(".pvtkey")) {
        keyName = keyName.slice(0, -7);
      }
      if (keyStore[keyName]) {
        alert(t('alert_priv_exists', {name: keyName}));
        continue;
      }
      const keyPair = await importPrivateKeyFromXmlUnified(text, keyName);
      keyStore[keyPair.name] = { 
        publicKey: keyPair.publicKey, 
        privateKey: keyPair.privateKey, 
        type: keyPair.type,
        curve: keyPair.curve,
        fingerprint: keyPair.fingerprint 
      };
      importedPrivateKeys.push({ name: keyPair.name, identifier: keyPair.identifier, cryptoKey: keyPair.privateKey, type: keyPair.type });
      
      const li = document.createElement('li');
      li.textContent = keyPair.name + " (" + keyPair.type + ")";
      privKeyListElem.appendChild(li);
      
      const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
      await storeKeyPair(keyPair.name, keyPair.type, publicJwk, privateJwk);
      refreshKeyList();
      clearExportArea();
      imported = true;
    } catch(err) {
      alert(t('alert_import_priv_err', {name: file.name}) + err.message);
    }
  }
  e.target.value = "";
  if(imported){
    alert(t('alert_import_priv_done'));
  }
  resetUI();
});

// ── ファイル暗号化処理 ──
async function encryptFile(file) {
  const aesKey = await crypto.subtle.generateKey(
    { name: AES_ALGORITHM, length: AES_KEY_LENGTH },
    true, ["encrypt", "decrypt"]
  );
  const aesKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", aesKey));
  const iv = window.crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));

  if (encryptionPublicKeys.length === 0) {
    throw new Error("No public key imported for encryption.");
  }
  const uniquePublicKeys = [];
  const seen = new Set();
  for (let pub of encryptionPublicKeys) {
    if (seen.has(pub.identifier)) {
      continue;
    }
    seen.add(pub.identifier);
    uniquePublicKeys.push(pub);
  }
  const entries = [];
  const encoder = new TextEncoder();
  for (let pub of uniquePublicKeys) {
    if (pub.type === "EC") {
      try {
        const ephemeralKeyPair = await crypto.subtle.generateKey(
          { name: EC_ALGORITHM, namedCurve: pub.curve },
          true, ["deriveKey"]
        );
        const wrappingKey = await crypto.subtle.deriveKey(
          { name: EC_ALGORITHM, public: pub.cryptoKey },
          ephemeralKeyPair.privateKey,
          { name: AES_ALGORITHM, length: 256 },
          false, ["encrypt", "decrypt"]
        );
        const ephemeralPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeralKeyPair.publicKey));
        const wrappingIV = window.crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));
        const wrappingCiphertextBuffer = await crypto.subtle.encrypt(
          { name: AES_ALGORITHM, iv: wrappingIV },
          wrappingKey,
          aesKeyRaw
        );
        const wrappingCiphertext = new Uint8Array(wrappingCiphertextBuffer);
        const wrappingOutput = concatUint8Arrays([wrappingIV, wrappingCiphertext]);
        const recipientIdBytes = base64ToUint8Array(pub.identifier);
        entries.push({
          type: 1,
          recipientId: recipientIdBytes,
          ephemeralPub: ephemeralPubRaw,
          wrappingOutput: wrappingOutput
        });
      } catch (err) {
        console.error("EC Encrypt Fail: ", err);
      }
    }
  }
  if (entries.length === 0) {
    throw new Error("No valid public key available.");
  }
  const fileBuffer = new Uint8Array(await file.arrayBuffer());
  const fileNameBytes = encoder.encode(file.name);
  const payloadPlain = concatUint8Arrays([writeInt32LE(fileNameBytes.length), fileNameBytes, fileBuffer]);
  const payloadEnc = new Uint8Array(await crypto.subtle.encrypt(
    { name: AES_ALGORITHM, iv: iv },
    aesKey,
    payloadPlain
  ));
  let parts = [];
  parts.push(writeInt32LE(entries.length));
  for (let entry of entries) {
    parts.push(new Uint8Array([entry.type]));
    if (entry.type === 1) {
      parts.push(writeInt32LE(entry.recipientId.length));
      parts.push(entry.recipientId);
      parts.push(writeInt32LE(entry.ephemeralPub.length));
      parts.push(entry.ephemeralPub);
      parts.push(writeInt32LE(entry.wrappingOutput.length));
      parts.push(entry.wrappingOutput);
    }
  }
  parts.push(iv);
  parts.push(payloadEnc);
  const finalData = concatUint8Arrays(parts);
  const blob = new Blob([finalData], { type: "application/octet-stream" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = file.name + ".crypted";
  a.click();
}

// ── ファイル復号処理 ──
async function decryptFile(file) {
  try {
    if (importedPrivateKeys.length === 0) {
      throw new Error("No private key available for decryption.");
    }
    const fileBuffer = new Uint8Array(await file.arrayBuffer());
    const view = new DataView(fileBuffer.buffer);
    let offset = 0;
    if (fileBuffer.length < 4) {
      throw new Error("Invalid file.");
    }
    const entryCount = readInt32LE(view, offset);
    offset += 4;
    const headerEntries = [];
    const decoder = new TextDecoder();
    for (let i = 0; i < entryCount; i++) {
      const type = fileBuffer[offset];
      offset += 1;
      if (type === 1) {
        const idLen = readInt32LE(view, offset);
        offset += 4;
        const recipientId = fileBuffer.slice(offset, offset + idLen);
        offset += idLen;
        const ephLen = readInt32LE(view, offset);
        offset += 4;
        const ephemeralPub = fileBuffer.slice(offset, offset + ephLen);
        offset += ephLen;
        const wrapLen = readInt32LE(view, offset);
        offset += 4;
        const wrappingOutput = fileBuffer.slice(offset, offset + wrapLen);
        offset += wrapLen;
        headerEntries.push({ type: 1, recipientId: recipientId, ephemeralPub: ephemeralPub, wrappingOutput: wrappingOutput });
      } else {
        throw new Error("Unknown key entry type.");
      }
    }
    if (offset + AES_IV_LENGTH > fileBuffer.length) {
      throw new Error("Invalid file.");
    }
    const iv = fileBuffer.slice(offset, offset + AES_IV_LENGTH);
    offset += AES_IV_LENGTH;
    const payloadEnc = fileBuffer.slice(offset);
    let aesKeyRaw;
    let found = false;
    for (let entry of headerEntries) {
      if (entry.type === 1) {
        const entryIdBase64 = arrayBufferToBase64(entry.recipientId);
        for (let priv of importedPrivateKeys.filter(k => k.type === "EC")) {
          if (priv.identifier === entryIdBase64) {
            const ephemeralPubKey = await crypto.subtle.importKey(
              "raw", entry.ephemeralPub,
              { name: EC_ALGORITHM, namedCurve: keyStore[priv.name].curve },
              true, []
            );
            const wrappingKey = await crypto.subtle.deriveKey(
              { name: EC_ALGORITHM, public: ephemeralPubKey },
              priv.cryptoKey,
              { name: AES_ALGORITHM, length: 256 },
              false, ["decrypt"]
            );
            const wrappingIV = entry.wrappingOutput.slice(0, AES_IV_LENGTH);
            const wrappingCiphertext = entry.wrappingOutput.slice(AES_IV_LENGTH);
            try {
              const decrypted = await crypto.subtle.decrypt(
                { name: AES_ALGORITHM, iv: wrappingIV },
                wrappingKey,
                wrappingCiphertext
              );
              aesKeyRaw = new Uint8Array(decrypted);
              found = true;
              break;
            } catch (err) { }
          }
        }
      }
      if (found) break;
    }
    if (!found || !aesKeyRaw) {
      throw new Error("Matching private key not found or AES decryption failed.");
    }
    const aesKey = await crypto.subtle.importKey("raw", aesKeyRaw, { name: AES_ALGORITHM }, true, ["decrypt"]);
    let payloadPlainBuffer;
    try {
      payloadPlainBuffer = await crypto.subtle.decrypt({ name: AES_ALGORITHM, iv: iv }, aesKey, payloadEnc);
    } catch (err) {
      throw new Error("AES decryption failed: " + err.message);
    }
    const payloadPlain = new Uint8Array(payloadPlainBuffer);
    const dv = new DataView(payloadPlain.buffer);
    if (payloadPlain.length < 4) {
      throw new Error("Decryption result is invalid.");
    }
    const fnameLen = dv.getInt32(0, true);
    if (4 + fnameLen > payloadPlain.length) {
      throw new Error("Decryption result is invalid.");
    }
    const fnameBytes = payloadPlain.slice(4, 4 + fnameLen);
    const originalFileName = decoder.decode(fnameBytes);
    const fileContent = payloadPlain.slice(4 + fnameLen);
    const blob = new Blob([fileContent], { type: "application/octet-stream" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = originalFileName;
    a.click();
  } catch (err) {
    throw err;
  }
}

// ── ボタン押下処理 ──
document.getElementById('encryptBtn').addEventListener('click', async () => {
  if (filesToProcess.length === 0) {
    alert(t('alert_no_file_enc'));
    return;
  }
  showSpinner(t('msg_enc_start'));
  let successCount = 0;
  let failCount = 0;

  for (let file of filesToProcess) {
    updateSpinnerText(t('msg_enc_processing', {name: file.name}));
    try {
      await encryptFile(file);
      successCount++;
    } catch (e) {
      console.error(e);
      failCount++;
    }
  }
  resetUIEncrypt();
  hideSpinner();
  alert(t('alert_done_result', {success: successCount, fail: failCount}));
});

document.getElementById('decryptBtn').addEventListener('click', async () => {
  if (filesToProcess.length === 0) {
    alert(t('alert_no_file_dec'));
    return;
  }
  showSpinner(t('msg_dec_start'));
  let successCount = 0;
  let failCount = 0;

  for (let file of filesToProcess) {
    updateSpinnerText(t('msg_dec_processing', {name: file.name}));
    try {
      await decryptFile(file);
      successCount++;
    } catch (e) {
      console.error(e);
      failCount++;
    }
  }
  resetUI();
  hideSpinner();
  alert(t('alert_done_result', {success: successCount, fail: failCount}));
});

// ── 鍵生成 ──
async function generateKeyPair(name, algType) {
  if (algType === "EC") {
    try {
      const keyPair = await crypto.subtle.generateKey(
        { name: EC_ALGORITHM, namedCurve: DEFAULT_EC_CURVE },
        true, ["deriveKey", "deriveBits"]
      );
      const fingerprint = await calcFingerprint(keyPair.publicKey);
      keyStore[name] = { 
        publicKey: keyPair.publicKey, 
        privateKey: keyPair.privateKey, 
        type: "EC",
        curve: DEFAULT_EC_CURVE,
        fingerprint: fingerprint
      };
      const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
      await storeKeyPair(name, "EC", publicJwk, privateJwk);
      const raw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
      const identifier = arrayBufferToBase64(raw);
      importedPrivateKeys.push({ name: name, identifier: identifier, cryptoKey: keyPair.privateKey, type: "EC" });
      alert(t('alert_ec_gen_done', {name: name}));
      refreshKeyList();
    } catch (e) {
      console.error(e);
      alert(t('alert_ec_gen_err') + e);
    }
  } else {
    alert(t('alert_unsupported_alg'));
  }
}

// ── 公開鍵URL共有機能 ──
async function exportPubkeyUrl(name) {
    const keyPair = keyStore[name];
    if (!keyPair || !keyPair.publicKey) {
        alert(t('alert_pub_not_found'));
        return;
    }

    const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const xml = convertPublicJwkToXml(jwk);
    const utf8 = new TextEncoder().encode(xml);
    const b64 = btoa(String.fromCharCode(...utf8));
    const b64url = base64ToBase64Url(b64);
    
    // 【確認】フィンガープリント取得
    const fingerprint = keyPair.fingerprint;
    // 【確認】URLパラメータに fp を付与
    const url = `${PUBKEY_SHARE_BASE_URL}#pubkey=${b64url}&fp=${fingerprint}`;

    const exportArea = document.getElementById("exportArea");
    clearExportArea();
    dispExportArea();

    const h3 = document.createElement("h3");
    h3.textContent = t('label_pub_url', {name: name});
    exportArea.appendChild(h3);

    const input = document.createElement("input");
    input.type = "text";
    input.value = url;
    input.readOnly = true;
    input.style.width = "98%";
    exportArea.appendChild(input);
    exportArea.appendChild(document.createElement("br"));

    const button = document.createElement("button");
    button.textContent = t('btn_copy_url');
    button.addEventListener("click", () => {
        navigator.clipboard.writeText(url);
        button.textContent = t('copied');
    });
    exportArea.appendChild(button);

    const p = document.createElement("p");
    p.textContent = t('label_pub_url_desc');
    exportArea.appendChild(p);

    const qrContainer = document.createElement("div");
    qrContainer.id = "qrcode";
    qrContainer.style.marginTop = "16px";
    exportArea.appendChild(qrContainer);

    new QRCode(qrContainer, {
        text: url,
        width: QR_CODE_SIZE,
        height: QR_CODE_SIZE,
        correctLevel: QR_CODE_CORRECT_LEVEL
    });
}

// ── 鍵一覧の再表示 ──
function refreshKeyList() {
  const tbody = document.getElementById("keyTable").querySelector("tbody");
  tbody.textContent = "";
  for (const name in keyStore) {
    const tr = document.createElement("tr");
    const tdName = document.createElement("td");
    tdName.textContent = name;
    tr.appendChild(tdName);

    const tdType = document.createElement("td");
    tdType.textContent = keyStore[name].type;
    tr.appendChild(tdType);

    const tdKeyInfo = document.createElement("td");
    if (keyStore[name].type === "EC") {
      const curveInfo = document.createTextNode(`Curve: ${keyStore[name].curve ? keyStore[name].curve : "N/A"}`);
      const br = document.createElement("br");
      const fpSpan = document.createElement("span");
      fpSpan.style.fontSize = "0.91em";
      fpSpan.style.color = "#777";
      fpSpan.textContent = `${t('fingerprint')}: ${keyStore[name].fingerprint ? keyStore[name].fingerprint : "N/A"}`;
      
      const copyBtn = document.createElement("button");
      copyBtn.textContent = t('copy');
      copyBtn.style.marginLeft = "6px";
      copyBtn.style.fontSize = "0.9em";
      copyBtn.style.padding = "2px 8px";
      copyBtn.onclick = () => {
          navigator.clipboard.writeText(keyStore[name].fingerprint);
          alert(t('copied'));
      };
      
      tdKeyInfo.appendChild(curveInfo);
      tdKeyInfo.appendChild(br);
      tdKeyInfo.appendChild(fpSpan);
      tdKeyInfo.appendChild(copyBtn);
    } else {
      tdKeyInfo.textContent = "N/A";
    }
    tr.appendChild(tdKeyInfo);

    const tdOps = document.createElement("td");

    const exportPubBtn = document.createElement("button");
    exportPubBtn.textContent = t('export_pub');
    exportPubBtn.onclick = () => exportKey(name, "public");

    const exportPubUrlBtn = document.createElement("button");
    exportPubUrlBtn.textContent = t('share_url');
    exportPubUrlBtn.onclick = () => exportPubkeyUrl(name);

    const exportPrivBtn = document.createElement("button");
    exportPrivBtn.textContent = t('export_priv');
    exportPrivBtn.classList.add('export-privkey-btn');
    exportPrivBtn.onclick = () => {
      if (confirm(t('confirm_priv_export'))) {
        exportKey(name, "private");
      }
    };

    const deleteBtn = document.createElement("button");
    deleteBtn.textContent = t('delete');
    deleteBtn.onclick = () => deleteKey(name);

    tdOps.appendChild(exportPubBtn);
    tdOps.appendChild(document.createTextNode(" "));
    tdOps.appendChild(exportPubUrlBtn);
    tdOps.appendChild(document.createTextNode(" "));
    tdOps.appendChild(exportPrivBtn);
    tdOps.appendChild(document.createTextNode(" "));
    tdOps.appendChild(deleteBtn);
    tr.appendChild(tdOps);

    tbody.appendChild(tr);
  }
}

// ── 鍵エクスポート ──
function convertPublicJwkToXml(jwk) {
  if (jwk.kty === "EC") {
    return `<ECKeyValue><Curve>${jwk.crv}</Curve><X>${jwk.x}</X><Y>${jwk.y}</Y></ECKeyValue>`;
  }
}
function convertPrivateJwkToXml(jwk) {
  if (jwk.kty === "EC") {
    return `<ECKeyValue><Curve>${jwk.crv}</Curve><X>${jwk.x}</X><Y>${jwk.y}</Y><D>${jwk.d}</D></ECKeyValue>`;
  }
}
async function exportKey(name, type) {
  const keyPair = keyStore[name];
  let key;
  if (type === "public") {
    if (!keyPair.publicKey) { alert(t('err_no_pub_exists')); return; }
    key = keyPair.publicKey;
  } else if (type === "private") {
    if (!keyPair.privateKey) { alert(t('err_no_priv_exists')); return; }
    key = keyPair.privateKey;
  }
  try {
    const jwk = await crypto.subtle.exportKey("jwk", key);
    let xml;
    if (type === "public") {
      xml = convertPublicJwkToXml(jwk);
    } else {
      xml = convertPrivateJwkToXml(jwk);
    }
    const exportArea = document.getElementById("exportArea");
    clearExportArea();
    dispExportArea();
    
    const h3 = document.createElement("h3");
    if (type === "private") {
      h3.textContent = t('header_export_priv', {name: name});
      exportArea.appendChild(h3);
      
      const p = document.createElement("p");
      p.style.color = "red";
      p.style.fontWeight = "bold";
      p.textContent = t('warn_priv_sensitive');
      exportArea.appendChild(p);
    } else {
      h3.textContent = t('header_export_pub', {name: name});
      exportArea.appendChild(h3);
    }
    
    const textarea = document.createElement("textarea");
    textarea.rows = 10;
    textarea.value = xml;
    exportArea.appendChild(textarea);

    const blob = new Blob([xml], { type: "application/xml" });
    const url = URL.createObjectURL(blob);

    const downloadBtn = document.createElement("button");
    downloadBtn.textContent = (type === "public" ? t('btn_download_pub') : t('btn_download_priv'));
    downloadBtn.style.marginTop = "8px";
    if (type === "private") {
      downloadBtn.style.backgroundColor = "#e53935";
      downloadBtn.style.color = "#fff";
      downloadBtn.style.border = "none";
    } else {
      downloadBtn.style.backgroundColor = "#2979ff";
      downloadBtn.style.color = "#fff";
      downloadBtn.style.border = "none";
    }
    downloadBtn.style.padding = "8px 16px";
    downloadBtn.style.borderRadius = "6px";
    downloadBtn.style.fontWeight = "bold";
    downloadBtn.onclick = function() {
      const a = document.createElement("a");
      a.href = url;
      a.download = name + (type === "public" ? ".pubkey" : ".pvtkey");
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    };

    exportArea.appendChild(document.createElement("br"));
    exportArea.appendChild(downloadBtn);
  } catch (e) {
    console.error(e);
    alert(t('err_export_fail') + e);
  }
}

async function deleteKey(name) {
  if (!confirm(t('confirm_delete', {name: name}))) return;
  try {
    await deleteKeyRecord(name);
  } catch (e) {
    console.error("DB削除エラー", e);
  }
  delete keyStore[name];
  let privIndex = importedPrivateKeys.findIndex(k => k.name === name);
  if (privIndex >= 0) { importedPrivateKeys.splice(privIndex, 1); }
  alert(t('alert_deleted', {name: name}));
  clearExportArea();
  refreshKeyList();
}
document.getElementById("generateKeyButton").addEventListener("click", async function() {
  const keyName = document.getElementById("keyNameInput").value.trim();
  const regex = /^[A-Za-z0-9_\-@\.]+$/;
  if (!regex.test(keyName)) {
    alert(t('alert_keyname_invalid'));
    return;
  }
  if (keyStore[keyName]) {
    alert(t('alert_keyname_exists'));
    return;
  }
  const algSelect = document.getElementById("keyAlgorithmSelect");
  const algType = algSelect.value;
  await generateKeyPair(keyName, algType);
});

// ── IndexedDB初期化（リセット） ──
function resetDatabase() {
  if (!confirm(t('confirm_reset_db'))) return;
  if (db) { db.close(); }
  const req = indexedDB.deleteDatabase("PubliCryptDB");
  req.onsuccess = function() {
    alert(t('alert_reset_done'));
    for (let key in keyStore) { delete keyStore[key]; }
    importedPrivateKeys.length = 0;
    clearExportArea();
    db = null;
    refreshKeyList();
    initDB();
  };
  req.onerror = function(e) {
    alert(t('alert_reset_err'));
  };
  req.onblocked = function(e) {
    alert(t('alert_blocked'));
  };
}
document.getElementById('resetDBBtn').addEventListener('click', resetDatabase);

// ── ページ起動時: #pubkey= で公開鍵を読み込む ──
function setBlocksDisplay(ids, displayStyle) {
  ids.forEach(id => {
    let el = document.getElementById(id);
    if (el) {
      el.style.display = displayStyle;
    } else {
      let classElems = document.getElementsByClassName(id);
      for (let i = 0; i < classElems.length; i++) {
        classElems[i].style.display = displayStyle;
      }
    }
  });
}

async function tryLoadPubkeyFromHash() {
  if (location.hash.startsWith("#pubkey=")) {
    try {
      let hash = location.hash.slice(1);
      let params = new URLSearchParams(hash.replace(/&/g,'&'));
      let b64url = params.get('pubkey');
      
      // 【確認】検証用フィンガープリント取得
      let expectedFp = params.get('fp');

      if (!b64url) throw "Public key data not found";
      const b64 = base64UrlToBase64(b64url);
      const bin = atob(b64);
      const uint8 = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; ++i) uint8[i] = bin.charCodeAt(i);
      const xml = new TextDecoder().decode(uint8);
      const pubKey = await importPublicKeyFromXmlUnified(xml, "URL受信公開鍵");
      encryptionPublicKeys.push(pubKey);

      // 【確認】フィンガープリントの検証ロジック
      if (expectedFp && pubKey.fingerprint !== expectedFp) {
        alert(t('alert_url_pub_mismatch', {expected: expectedFp, actual: pubKey.fingerprint}));
      } else {
        const li = document.createElement('li');
        const keyInfoDiv = document.createElement('div');
        keyInfoDiv.textContent = `${pubKey.name} (${pubKey.type})`;
        const br = document.createElement('br');
        const fpSpan = document.createElement('span');
        fpSpan.style.fontSize = "0.91em";
        fpSpan.style.color = "#777";
        fpSpan.textContent = `${t('fingerprint')}: ${pubKey.fingerprint}`;
        const copyBtn = document.createElement('button');
        copyBtn.textContent = t('copy');
        copyBtn.style.marginLeft = "6px";
        copyBtn.style.fontSize = "0.9em";
        copyBtn.style.padding = "2px 8px";
        copyBtn.onclick = () => {
            navigator.clipboard.writeText(pubKey.fingerprint);
            alert(t('copied'));
        };
        
        li.appendChild(keyInfoDiv);
        li.appendChild(br);
        li.appendChild(fpSpan);
        li.appendChild(copyBtn);
        
        document.getElementById('pubKeyList').appendChild(li);
        alert(t('alert_url_pub_ok', {fp: pubKey.fingerprint}));
        setBlocksDisplay(HIDEABLE_UI_BLOCK_IDS, "none");
      }
    } catch (e) {
      alert(t('alert_url_load_err') + e);
    }
  }
}

// ── マジックリンク機能 ──

// 1. 送信者: リクエストURLを作成して表示
function createMagicLink() {
  const senderName = prompt(t('magic_req_prompt'), "Alice");
  if (!senderName) return;

  // 現在のベースURL (index.htmlまでのパス) を取得
  const baseUrl = window.location.href.split('#')[0];
  
  // URLフラグメントを作成
  const fragment = `${MAGIC_REQ_PARAM}=1&${MAGIC_SENDER_PARAM}=${encodeURIComponent(senderName)}`;
  const fullUrl = `${baseUrl}#${fragment}`;

  // エクスポートエリアに表示
  const exportArea = document.getElementById("exportArea");
  clearExportArea();
  dispExportArea();

  const h3 = document.createElement("h3");
  h3.textContent = t('magic_link_header');
  exportArea.appendChild(h3);

  const p = document.createElement("p");
  p.textContent = t('magic_link_desc');
  exportArea.appendChild(p);

  const input = document.createElement("input");
  input.type = "text";
  input.value = fullUrl;
  input.readOnly = true;
  input.style.width = "98%";
  exportArea.appendChild(input);

  const button = document.createElement("button");
  button.textContent = t('btn_copy_url'); 
  button.addEventListener("click", () => {
      navigator.clipboard.writeText(fullUrl);
      button.textContent = t('copied');
  });
  exportArea.appendChild(button);
  
  // QRコードも表示
  const qrContainer = document.createElement("div");
  qrContainer.style.marginTop = "16px";
  new QRCode(qrContainer, {
        text: fullUrl,
        width: QR_CODE_SIZE,
        height: QR_CODE_SIZE,
        correctLevel: QR_CODE_CORRECT_LEVEL
  });
  exportArea.appendChild(qrContainer);
}

// 2. 受信者: ウィザード画面の制御
async function checkMagicLinkRequest() {
  if (!location.hash.includes(`${MAGIC_REQ_PARAM}=1`)) return;

  // URLパラメータ解析
  const hash = location.hash.slice(1);
  const params = new URLSearchParams(hash);
  const sender = params.get(MAGIC_SENDER_PARAM) || "Sender";

  // 通常UIを隠し、ウィザードを表示
  const mainApp = document.getElementById('main-app-container');
  if(mainApp) mainApp.style.display = 'none';
  
  const wizard = document.getElementById('magicLinkWizard');
  wizard.style.display = 'block';

  // ウィザードのテキスト設定
  document.getElementById('wizardTitle').textContent = t('wizard_title', {sender: sender});
  document.getElementById('wizardDesc').innerHTML = t('wizard_desc', {sender: sender});
  
  const startBtn = document.getElementById('wizardStartBtn');
  startBtn.textContent = t('wizard_btn_start');

  startBtn.onclick = async () => {
    // ボタン無効化 & スピナー
    startBtn.disabled = true;
    startBtn.textContent = t('processing');

    try {
      // 自動的にユニークな鍵名を生成 (例: Guest_20251224_1234)
      const now = new Date();
      const keyName = `Guest_${now.getFullYear()}${(now.getMonth()+1).toString().padStart(2,'0')}${now.getDate().toString().padStart(2,'0')}_${now.getHours()}${now.getMinutes()}`;
      
      // 既存の鍵生成関数を利用
      await generateKeyPair(keyName, "EC"); // IndexedDBに保存される
      
      // 生成された鍵を取得してエクスポート用URLを作成
      const keyPair = keyStore[keyName];
      const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const xml = convertPublicJwkToXml(jwk);
      const utf8 = new TextEncoder().encode(xml);
      const b64 = btoa(String.fromCharCode(...utf8));
      const b64url = base64ToBase64Url(b64);
      const fingerprint = keyPair.fingerprint;

      // 返信URL構築 (既存のPubliCryptが読み込める形式 #pubkey=...)
      // 送信者がこのURLを開くと、自動的に鍵がインポートされる
      const baseUrl = window.location.href.split('#')[0];
      const replyUrl = `${baseUrl}#pubkey=${b64url}&fp=${fingerprint}`;

      // 結果表示
      document.getElementById('wizardStep1').style.display = 'none';
      const resultArea = document.getElementById('wizardResult');
      resultArea.style.display = 'block';
      
      document.getElementById('wizardDoneMsg').textContent = t('wizard_step_done');
      document.getElementById('wizardReplyInst').textContent = t('wizard_reply_inst', {sender: sender});
      
      const replyInput = document.getElementById('wizardReplyUrl');
      replyInput.value = replyUrl;
      
      const copyBtn = document.getElementById('wizardCopyBtn');
      copyBtn.textContent = t('btn_copy_reply_url');
      copyBtn.onclick = () => {
        navigator.clipboard.writeText(replyUrl);
        copyBtn.textContent = t('copied');
      };
      
      // QRコード
      new QRCode(document.getElementById('wizardQr'), {
        text: replyUrl,
        width: 256,
        height: 256,
        correctLevel: QRCode.CorrectLevel.L
      });

    } catch (e) {
      console.error(e);
      alert("Error: " + e);
      startBtn.disabled = false;
    }
  };
}

// ── 初期化処理 ──
window.addEventListener("load", async () => {
  // 言語検出
  const userLang = (navigator.language || navigator.userLanguage).toLowerCase(); 
  if (userLang.startsWith('ja')) {
      currentLang = 'ja';
  } else if (userLang.startsWith('fr')) {
      currentLang = 'fr';
  } else if (userLang.startsWith('lb')) {
      currentLang = 'lb';
  } else {
      currentLang = 'en';
  }
  updateUIText(); 

  await initDB();
  await tryLoadPubkeyFromHash();
  await checkMagicLinkRequest(); // マジックリンクチェック
});

// イベントリスナー
document.getElementById('lang-ja').addEventListener('click', () => changeLanguage('ja'));
document.getElementById('lang-en').addEventListener('click', () => changeLanguage('en'));
document.getElementById('lang-fr').addEventListener('click', () => changeLanguage('fr'));
document.getElementById('lang-lb').addEventListener('click', () => changeLanguage('lb'));

document.getElementById('resetUiBtn').addEventListener('click', async () => {
  resetUI();
});
document.getElementById('reloadURLBtn').addEventListener('click', async () => {
  resetUI();
  await tryLoadPubkeyFromHash();
});

const magicLinkBtn = document.getElementById('createMagicLinkBtn');
if(magicLinkBtn) {
    magicLinkBtn.addEventListener('click', createMagicLink);
}

window.addEventListener("DOMContentLoaded", hideResetUiButtonsInExtension);
